-- ─────────────────────────────────────────────────────────────────────
--  Recipient-side unshare
--
--  Lets a share recipient remove their own setlist_shares row. Without
--  this policy, the existing RLS only allowed the setlist OWNER to
--  delete share rows, so "Remove from my list" couldn't do anything
--  on the server — the app would clear it locally and the next load
--  would re-fetch it from the cloud.
--
--  Scope: a user can ONLY delete share rows where they are the
--  recipient (shared_with = auth.uid()). They cannot delete other
--  people's share rows, so the owner's shares with everyone else are
--  completely safe.
-- ─────────────────────────────────────────────────────────────────────

drop policy if exists shares_recipient_delete on public.setlist_shares;
create policy shares_recipient_delete on public.setlist_shares
  for delete
  using (shared_with = auth.uid());
