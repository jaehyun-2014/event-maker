-- EVENT MAKER Supabase DB fix
-- Supabase SQL Editor에서 한 번 실행하세요.

create extension if not exists pgcrypto;

alter table public.rooms
  add column if not exists description text default '',
  add column if not exists password_hash text default '',
  add column if not exists icon_url text default '';

alter table public.room_members
  add column if not exists role text default 'member';

update public.room_members rm
set role = 'owner'
from public.rooms r
where rm.room_id = r.id
  and rm.user_id = r.created_by
  and coalesce(rm.role,'') <> 'owner';

create or replace function public.is_room_member(target_room uuid)
returns boolean language sql security definer stable set search_path = public
as $$
  select exists(
    select 1 from public.room_members rm
    where rm.room_id = target_room and rm.user_id = auth.uid()
  );
$$;

create or replace function public.is_room_owner(target_room uuid)
returns boolean language sql security definer stable set search_path = public
as $$
  select exists(
    select 1 from public.room_members rm
    where rm.room_id = target_room and rm.user_id = auth.uid() and rm.role = 'owner'
  );
$$;

drop function if exists public.create_room(text,text,text);

create or replace function public.create_room(
  room_name text, room_description text, room_password text
)
returns uuid language plpgsql security definer set search_path = public
as $$
declare
  new_room_id uuid;
  hashed_password text;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;
  if trim(coalesce(room_name,'')) = '' then raise exception '방 이름을 입력해주세요.'; end if;
  if coalesce(room_password,'') = '' then raise exception '방 비밀번호를 입력해주세요.'; end if;

  hashed_password := crypt(room_password, gen_salt('bf'));

  insert into public.rooms (name, description, password_hash, created_by, created_at)
  values (trim(room_name), coalesce(room_description,''), hashed_password, auth.uid(), now())
  returning id into new_room_id;

  insert into public.room_members (room_id, user_id, role)
  values (new_room_id, auth.uid(), 'owner');

  return new_room_id;
end;
$$;

drop function if exists public.join_room(uuid,text);

create or replace function public.join_room(
  target_room uuid, room_password text
)
returns boolean language plpgsql security definer set search_path = public
as $$
declare stored_password text;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;

  select password_hash into stored_password
  from public.rooms where id = target_room;

  if stored_password is null or stored_password = '' then return false; end if;

  if stored_password = crypt(room_password, stored_password) then
    insert into public.room_members (room_id, user_id, role)
    values (target_room, auth.uid(), 'member')
    on conflict (room_id, user_id) do nothing;
    return true;
  end if;

  return false;
end;
$$;

drop policy if exists "room members can view rooms" on public.rooms;
drop policy if exists "owners can update rooms" on public.rooms;
drop policy if exists "owners can delete rooms" on public.rooms;
drop policy if exists "members can view their memberships" on public.room_members;

create policy "room members can view rooms"
on public.rooms for select to authenticated
using (public.is_room_member(id));

create policy "owners can update rooms"
on public.rooms for update to authenticated
using (public.is_room_owner(id))
with check (public.is_room_owner(id));

create policy "owners can delete rooms"
on public.rooms for delete to authenticated
using (public.is_room_owner(id));

create policy "members can view their memberships"
on public.room_members for select to authenticated
using (user_id = auth.uid());
