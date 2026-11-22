alter table public.stores
  add column if not exists destination_url text,
  add column if not exists is_active boolean not null default true;

comment on column public.stores.destination_url is
  'Destination used by the permanent QR code generated for this shop';
