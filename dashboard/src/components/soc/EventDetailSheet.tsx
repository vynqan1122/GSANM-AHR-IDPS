import { Sheet } from '@/components/ui/overlays';
import { fmtDateTime, fmtScore } from '@/lib/format';
import type { EventRow } from '@/types/api';
import { Field, JsonView, Mono, RiskBadge, ScoreBar, SectionLabel, SeverityBadge, SourceBadge } from './primitives';

const AI_SCORES: Array<[keyof NonNullable<EventRow['ai']>, string]> = [
  ['rule_score', 'Rule'],
  ['network_score', 'Network AI'],
  ['log_score', 'Log AI'],
  ['graph_score', 'Graph AI'],
  ['context_score', 'Context'],
];

export function EventDetailSheet({ event, onClose }: { event: EventRow | null; onClose: () => void }) {
  return (
    <Sheet
      open={event !== null}
      onOpenChange={(open) => !open && onClose()}
      title="Chi tiết sự kiện"
      description={event ? `event_id ${event.event_id}` : undefined}
    >
      {event && (
        <div className="flex flex-col gap-5">
          <div className="grid grid-cols-2 gap-2">
            <Field label="Thời gian">{fmtDateTime(event.timestamp)}</Field>
            <Field label="Sensor nguồn">
              <SourceBadge source={event.source} />
            </Field>
            <Field label="Loại sự kiện">{event.event_type || '—'}</Field>
            <Field label="Severity">
              <SeverityBadge severity={event.severity} />
            </Field>
          </div>

          <section>
            <SectionLabel>Fusion score</SectionLabel>
            <div className="rounded-lg border border-border bg-background/40 p-3">
              <div className="mb-3 flex items-center justify-between">
                <span className="num text-2xl font-semibold">{fmtScore(event.ai?.fusion_score)}</span>
                <RiskBadge level={event.ai?.risk_level} />
              </div>
              {event.ai ? (
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {AI_SCORES.map(([key, label]) => (
                    <div key={key} className="flex items-center justify-between gap-2 text-xs">
                      <span className="text-muted-foreground">{label}</span>
                      <ScoreBar value={event.ai?.[key] as number | null | undefined} />
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">Sự kiện chưa có điểm AI.</p>
              )}
            </div>
          </section>

          <section>
            <SectionLabel>Mạng và container</SectionLabel>
            <div className="grid grid-cols-2 gap-2">
              <Field label="IP nguồn">{event.src_ip ? <Mono>{event.src_ip}</Mono> : '—'}</Field>
              <Field label="IP đích">{event.dst_ip ? <Mono>{event.dst_ip}</Mono> : '—'}</Field>
              <Field label="Container">{event.container?.name || '—'}</Field>
              <Field label="Image">{event.container?.image ? <Mono>{event.container.image}</Mono> : '—'}</Field>
              <Field label="Rule" className="col-span-2">
                {event.rule?.name || event.rule?.rule_id || '—'}
              </Field>
            </div>
          </section>

          <section>
            <SectionLabel>Payload gốc</SectionLabel>
            <JsonView value={event} />
          </section>
        </div>
      )}
    </Sheet>
  );
}
