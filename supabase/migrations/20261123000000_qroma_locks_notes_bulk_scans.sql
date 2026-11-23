-- QROMA: item locks, private notes, and selected scan-history management.
alter table public.qr_codes
  add column if not exists is_locked boolean not null default false;

alter table public.stores
  add column if not exists is_locked boolean not null default false;

create table if not exists public.qroma_notes (
  id uuid primary key default gen_random_uuid(),
  store_id uuid null references public.stores(id) on delete set null,
  code text null references public.qr_codes(code) on delete set null,
  note text not null check (char_length(trim(note)) between 1 and 4000),
  status text not null default 'pending' check (status in ('done', 'pending', 'rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
);

create index if not exists qroma_notes_store_id_idx on public.qroma_notes(store_id);
create index if not exists qroma_notes_code_idx on public.qroma_notes(code);
create index if not exists qroma_notes_created_at_idx on public.qroma_notes(created_at desc);

alter table public.qroma_notes enable row level security;
revoke all on public.qroma_notes from public, anon, authenticated;
grant select, insert, update, delete on public.qroma_notes to service_role;

-- Selected scan operations use the same baseline model as the existing global reset.
drop function if exists public.qroma_manage_scans(text);
create or replace function public.qroma_manage_scans(action text, codes text[] default null)
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
    where codes is null or q.code = any(codes)
    group by q.code
    on conflict (code) do update
      set baseline_scan_id = excluded.baseline_scan_id,
          reset_at = excluded.reset_at;
    get diagnostics affected = row_count;
    return jsonb_build_object('success', true, 'action', action, 'codes_reset', affected);
  elsif action = 'delete_history' then
    if codes is null or cardinality(codes) = 0 then
      raise exception 'Select one or more QR codes';
    end if;
    delete from public.qr_scans where code = any(codes);
    get diagnostics affected = row_count;
    delete from private.qr_scan_baselines where code = any(codes);
    return jsonb_build_object('success', true, 'action', action, 'deleted_scans', affected);
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

revoke all on function public.qroma_manage_scans(text, text[]) from public, anon, authenticated;
grant execute on function public.qroma_manage_scans(text, text[]) to service_role;

create or replace function public.qroma_delete_scan_baseline(target_code text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected integer := 0;
begin
  delete from private.qr_scan_baselines where code = target_code;
  get diagnostics affected = row_count;
  return jsonb_build_object('success', true, 'deleted_baselines', affected);
end;
$$;

revoke all on function public.qroma_delete_scan_baseline(text) from public, anon, authenticated;
grant execute on function public.qroma_delete_scan_baseline(text) to service_role;

-- Remove the baseline row when an unlocked QR code is permanently deleted.
create or replace function public.qroma_delete_scan_baseline(target_code text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  affected integer := 0;
begin
  delete from private.qr_scan_baselines where code = target_code;
  get diagnostics affected = row_count;
  return jsonb_build_object('success', true, 'deleted_baselines', affected);
end;
$$;

revoke all on function public.qroma_delete_scan_baseline(text) from public, anon, authenticated;
grant execute on function public.qroma_delete_scan_baseline(text) to service_role;
