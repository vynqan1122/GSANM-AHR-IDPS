"""Local, offline inference for a merged fine-tuned model. No database or sensor access."""
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import threading
import time
import uuid

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, model_validator
from .contract import SYSTEM, decode_output, user_input, verify_bundle


class GenerateRequest(BaseModel):
    task: str = Field(min_length=10, max_length=2000)
    evidence: list[dict] = Field(min_length=1, max_length=5)
    benign_examples: list[dict] = Field(min_length=1, max_length=5)
    cti: dict = Field(default_factory=lambda: {'references': [], 'mitre_attack': []})

    @model_validator(mode='after')
    def bounded_payload(self):
        self.task = self.task.strip()
        if len(self.task) < 10:
            raise ValueError('Describe a meaningful detection task')
        for key in ('references', 'mitre_attack'):
            values = self.cti.get(key, [])
            if not isinstance(values, list) or len(values) > 10 or any(not isinstance(x, str) or len(x) > 500 for x in values):
                raise ValueError('Invalid CTI fields')
        if len(user_input(self.model_dump())) > 16000:
            raise ValueError('Evidence too large; select fewer events')
        return self


class ReviewRequest(BaseModel):
    events: list[dict] = Field(min_length=2, max_length=6)

    @model_validator(mode='after')
    def bounded_payload(self):
        if len(json.dumps(self.events)) > 12000:
            raise ValueError('Review observations too large')
        return self


class Engine:
    def __init__(self, folder):
        self.manifest = verify_bundle(folder)
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        torch.set_num_threads(int(os.getenv('GENTI_CPU_THREADS', '4')))
        self.tokenizer = AutoTokenizer.from_pretrained(folder, local_files_only=True, trust_remote_code=False)
        self.model = AutoModelForCausalLM.from_pretrained(folder, local_files_only=True,
            trust_remote_code=False, use_safetensors=True, torch_dtype=torch.float32,
            device_map='cpu', low_cpu_mem_usage=True)
        self.model.eval()

    def generate(self, request):
        messages = [{'role': 'system', 'content': SYSTEM},
                    {'role': 'user', 'content': user_input(request.model_dump())}]
        ids = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, return_tensors='pt')
        if ids.shape[1] > 1536:
            raise ValueError('Prompt exceeds 1536 tokens; reduce event count or task length')
        with self.torch.inference_mode():
            output = self.model.generate(ids, attention_mask=self.torch.ones_like(ids),
                max_new_tokens=512, do_sample=False, pad_token_id=self.tokenizer.eos_token_id)
        text = self.tokenizer.decode(output[0, ids.shape[1]:], skip_special_tokens=True)
        return decode_output(text, request.cti)


@asynccontextmanager
async def lifespan(app):
    app.state.engine = None
    app.state.error = None
    app.state.startup_id = uuid.uuid4().hex
    try:
        engine_class = Engine
        if os.getenv('GENTI_LLAMA_URL'):
            from .llama import LlamaEngine
            engine_class = LlamaEngine
        app.state.engine = engine_class(os.getenv('GENTI_MODEL_DIR', '/model'))
    except Exception as exc:
        app.state.error = type(exc).__name__
        logging.exception('GenTI model could not be loaded')
    yield


app = FastAPI(lifespan=lifespan)
lock = threading.Lock()


@app.get('/status')
def status():
    engine = app.state.engine
    ready = engine is not None
    error = app.state.error
    if ready and os.getenv('GENTI_LLAMA_URL'):
        try:
            engine.call('/health')
        except RuntimeError:
            ready = False
            error = 'Local GGUF inference server unavailable'
    report = {'status': 'pending'}
    try:
        saved = json.loads(Path(os.getenv('GENTI_TEST_REPORT', '/checks/latest.json')).read_text(encoding='utf-8'))
        if (engine and saved.get('startup_id') == app.state.startup_id and
                saved.get('artifact_sha256') == engine.manifest['artifact_sha256']):
            report = {k: saved[k] for k in ('status', 'startup_id', 'artifact_sha256', 'started_at', 'finished_at', 'error', 'scope') if k in saved}
    except (OSError, ValueError):
        pass
    return {'ready': ready, 'busy': lock.locked(), 'error': error,
            'model': engine.manifest if engine else None, 'device': 'cpu',
            'startup_id': app.state.startup_id, 'self_test': report,
            'role': 'rule_generation', 'sensor_deployed': False}


@app.post('/generate')
def generate(request: GenerateRequest):
    return infer(request, 'generate')


@app.post('/review')
def review(request: ReviewRequest):
    return infer(request, 'review')


def infer(request, operation):
    engine = app.state.engine
    if engine is None:
        raise HTTPException(503, 'Install the fine-tuned GenTI model first; see worker logs')
    if not hasattr(engine, operation):
        raise HTTPException(503, 'Installed runtime does not support evidence review')
    if not lock.acquire(blocking=False):
        raise HTTPException(429, 'GenTI is processing another request')
    started = time.perf_counter()
    try:
        result = getattr(engine, operation)(request)
        return {'output': result, 'artifact_sha256': engine.manifest['artifact_sha256'],
                'seconds': time.perf_counter()-started}
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    finally:
        lock.release()
