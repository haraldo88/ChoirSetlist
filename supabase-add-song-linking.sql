-- ─────────────────────────────────────────────────────────────────────
--  Song linking across setlists
--
--  Adds a 'linked_song_id' column so a song row in setlist B can point
--  at a canonical song row in setlist A. All data (name, tempo,
--  notes, sheet music) comes from the canonical; the link row itself
--  only exists to anchor the song inside its setlist's position list.
--
--  Semantics on the client:
--    • Rendering a linked song     — overlay the canonical's fields.
--    • Editing a linked song       — write to the canonical instead.
--    • Deleting a linked song      — removes just the link row.
--    • Deleting the canonical      — cascades to all its links (via
--                                    ON DELETE CASCADE below), which
--                                    is intentional: the "one true
--                                    version" is gone, so references
--                                    to it should go too.
-- ─────────────────────────────────────────────────────────────────────

alter table public.songs
  add column if not exists linked_song_id uuid
    references public.songs(id) on delete cascade;

create index if not exists songs_linked_song_id_idx
  on public.songs(linked_song_id);
