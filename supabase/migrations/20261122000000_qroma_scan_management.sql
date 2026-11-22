-- Preserve historical scan rows while allowing current counters to restart.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;
grant usage on schema private to service_role;

create table if not exists private.qr_scan_baselines (
  code text primary key,
  baseline_scan_id bigint not null default 0,
  reset_at timestamptz not null default now()
);
alter table private.qr_scan_baselines enable row level security;
revoke all on private.qr_scan_baselines from public, anon, authenticated, service_role;
grant select, insert, update, delete on private.qr_scan_baselines to service_role;

create or replace view public.qr_scan_stats as
select
  q.code,
  count(s.id) filter (where s.id > coalesce(b.baseline_scan_id, 0)) as scan_count,
  max(s.scanned_at) filter (where s.id > coalesce(b.baseline_scan_id, 0)) as last_scanned_at
from public.qr_codes q
left join public.qr_scans s on s.code = q.code
left join private.qr_scan_baselines b on b.code = q.code
group by q.code, b.baseline_scan_id;

create or replace function public.qroma_manage_scans(action text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected integer := 0;
begin
  if action = 'reset_counters' then
    insert into private.qr_scan_baselines (code, baseline_scan_id, reset_at)
    select q.code, coalesce(max(s.id), 0), now()
    from public.qr_codes q
    left join public.qr_scans s on s.code = q.code
    group by q.code
    on conflict (code) do update
      set baseline_scan_id = excluded.baseline_scan_id,
          reset_at = excluded.reset_at;
    get diagnostics affected = row_count;
    return jsonb_build_object('success', true, 'action', action, 'codes_reset', affected);
  elsif action = 'delete_all_history' then
    delete from public.qr_scans;
    get diagnostics affected = row_count;
    delete from private.qr_scan_baselines;
    return jsonb_build_object('success', true, 'action', action, 'deleted_scans', affected);
  else
    raise exception 'Unsupported scan action';
  end if;
end;
$$;

revoke all on function public.qroma_manage_scans(text) from public, anon, authenticated;
grant execute on function public.qroma_manage_scans(text) to service_role;
