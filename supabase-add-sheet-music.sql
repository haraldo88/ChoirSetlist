-- ─────────────────────────────────────────────────────────────────────
--  Sheet-music attachment support
--
--  Adds the ability to attach a PDF (sheet music) to each song. The
--  file itself lives in Supabase Storage so row size stays small; the
--  songs row only stores a path pointing into the bucket.
--
--  Access rules (same as the rest of the sharing model):
--    • Owner of the setlist           — full read/write
--    • Shared-edit recipient          — full read/write
--    • Shared-view recipient          — read only (can view the PDF)
--
--  Path convention inside the bucket:
--    "<setlist_id>/<song_id>.pdf"
--  so the storage policies can parse out the setlist_id and reuse the
--  existing user_owns_setlist / user_can_edit_setlist / user_can_view_setlist
--  helpers. One PDF per song (upload with upsert: true replaces).
-- ─────────────────────────────────────────────────────────────────────

-- ── Column on songs ────────────────────────────────────────────────────
alter table public.songs
  add column if not exists sheet_music_path text;

-- ── Private storage bucket ─────────────────────────────────────────────
-- 'public = false' means the files are only reachable via signed URLs
-- generated server-side after an RLS check — no one can guess a URL.
insert into storage.buckets (id, name, public)
values ('sheet-music', 'sheet-music', false)
on conflict (id) do nothing;

-- ── Helper: extract setlist_id from an object path ─────────────────────
-- Paths look like "<setlist_id>/<song_id>.pdf". This function returns
-- the leading UUID or null if the path isn't shaped that way. It's
-- immutable so Postgres can inline it inside policies.
create or replace function public.sheet_music_setlist_id(obj_name text)
returns uuid
language sql
immutable
as $$
  select case
    when obj_name is null then null
    else nullif(split_part(obj_name, '/', 1), '')::uuid
  end;
$$;

-- ── Storage RLS policies ───────────────────────────────────────────────
-- Four policies, one per command, all gated on setlist access via the
-- existing SECURITY DEFINER helpers so this stays consistent with the
-- rest of the sharing model.

drop policy if exists sheet_music_select on storage.objects;
create policy sheet_music_select on storage.objects
  for select
  using (
    bucket_id = 'sheet-music'
    and (
      public.user_owns_setlist   (public.sheet_music_setlist_id(name))
      or public.user_can_view_setlist(public.sheet_music_setlist_id(name))
    )
  );

drop policy if exists sheet_music_insert on storage.objects;
create policy sheet_music_insert on storage.objects
  for insert
  with check (
    bucket_id = 'sheet-music'
    and (
      public.user_owns_setlist   (public.sheet_music_setlist_id(name))
      or public.user_can_edit_setlist(public.sheet_music_setlist_id(name))
    )
  );

drop policy if exists sheet_music_update on storage.objects;
create policy sheet_music_update on storage.objects
  for update
  using (
    bucket_id = 'sheet-music'
    and (
      public.user_owns_setlist   (public.sheet_music_setlist_id(name))
      or public.user_can_edit_setlist(public.sheet_music_setlist_id(name))
    )
  );

drop policy if exists sheet_music_delete on storage.objects;
create policy sheet_music_delete on storage.objects
  for delete
  using (
    bucket_id = 'sheet-music'
    and (
      public.user_owns_setlist   (public.sheet_music_setlist_id(name))
      or public.user_can_edit_setlist(public.sheet_music_setlist_id(name))
    )
  );
