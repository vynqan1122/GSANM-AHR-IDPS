"""Offline GGUF inference behind the same app contract as the merged worker."""
import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .contract import GGUF_CONTRACT, SYSTEM, decode_output, user_input, verify_bundle
from .evidence_review import REVIEW_SYSTEM, decode_review


class LlamaEngine:
    def __init__(self, folder):
        self.manifest = verify_bundle(folder)
        if self.manifest['contract'] != GGUF_CONTRACT:
            raise ValueError('The llama runtime requires a verified GGUF bundle')
        self.url = os.environ['GENTI_LLAMA_URL'].rstrip('/')
        self.call('/health')

    def call(self, path, body=None):
        request = Request(self.url + path, data=None if body is None else json.dumps(body).encode(),
                          headers={'Content-Type': 'application/json'})
        try:
            with urlopen(request, timeout=600 if path == '/v1/chat/completions' else 1 if path == '/health' else 5) as response:
                return json.load(response)
        except (HTTPError, URLError, TimeoutError) as exc:
            raise RuntimeError('Local GGUF server unavailable; inspect genti-llama logs') from exc

    def complete(self, messages, max_tokens=512, schema=None):
        prompt = self.call('/apply-template', {'messages': messages})['prompt']
        tokens = self.call('/tokenize', {'content': prompt, 'add_special': True, 'parse_special': True})['tokens']
        if len(tokens) > 1536:
            raise ValueError('Prompt exceeds 1536 tokens; reduce event count or task length')
        response_format = {'type': 'json_object'}
        if schema:
            response_format['schema'] = schema
        response = self.call('/v1/chat/completions', {'model': 'genti', 'messages': messages,
            'temperature': 0, 'seed': 42, 'max_tokens': max_tokens, 'stream': False,
            'response_format': response_format})
        choice = response['choices'][0]
        if choice['finish_reason'] != 'stop':
            raise ValueError('Generation did not finish within the token limit; no candidate accepted')
        return choice['message']['content']

    def generate(self, request):
        messages = [{'role': 'system', 'content': SYSTEM},
                    {'role': 'user', 'content': user_input(request.model_dump())}]
        return decode_output(self.complete(messages), request.cti)

    def review(self, request):
        slots = {'type': 'array', 'items': {'type': 'integer', 'minimum': 0, 'maximum': len(request.events)-1}, 'maxItems': 3}
        schema = {'type': 'object', 'additionalProperties': False,
                  'properties': {'evidence': slots, 'benign': slots,
                                 'task': {'type': 'string'}, 'reason': {'type': 'string'}},
                  'required': ['evidence', 'benign', 'task', 'reason']}
        messages = [{'role': 'system', 'content': REVIEW_SYSTEM}, {'role': 'user', 'content': json.dumps(
            {'observations': [{'slot': i, **e} for i, e in enumerate(request.events)]}, ensure_ascii=False)}]
        return decode_review(self.complete(messages, max_tokens=320, schema=schema), len(request.events))
