-- EVENT MAKER Supabase DB fix
-- Supabase SQL Editor에서 이 파일 전체를 한 번 실행하세요.

-- Supabase에서는 pgcrypto 함수가 extensions 스키마에 설치되는 경우가 많습니다.
create schema if not exists extensions;
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pgcrypto') then
    begin
      alter extension pgcrypto set schema extensions;
    exception when others then
      null;
    end;
  else
    create extension pgcrypto with schema extensions;
  end if;
end
$$;

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
returns boolean language sql security definer stable set search_path = public, extensions
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
returns uuid language plpgsql security definer set search_path = public, extensions, extensions
as $$
declare
  new_room_id uuid;
  hashed_password text;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;
  if trim(coalesce(room_name,'')) = '' then raise exception '방 이름을 입력해주세요.'; end if;
  if coalesce(room_password,'') = '' then raise exception '방 비밀번호를 입력해주세요.'; end if;

  hashed_password := extensions.crypt(room_password, extensions.gen_salt('bf'));

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
returns boolean language plpgsql security definer set search_path = public, extensions
as $$
declare
  stored_password text;
begin
  if auth.uid() is null then raise exception '로그인이 필요합니다.'; end if;

  select password_hash into stored_password
  from public.rooms where id = target_room;

  if stored_password is null or stored_password = '' then return false; end if;

  if stored_password = extensions.crypt(room_password, stored_password) then
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


-- 방 참여 시 UUID 대신 방 이름으로 참여할 수 있게 합니다.
drop function if exists public.join_room_by_name(text,text);

create or replace function public.join_room_by_name(
  target_room_name text,
  room_password text
)
returns uuid
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  target_room_id uuid;
  stored_password text;
begin
  if auth.uid() is null then
    raise exception '로그인이 필요합니다.';
  end if;

  select id, password_hash
    into target_room_id, stored_password
  from public.rooms
  where name = trim(target_room_name)
  limit 1;

  if target_room_id is null or stored_password is null or stored_password = '' then
    return null;
  end if;

  if stored_password = extensions.crypt(room_password, stored_password) then
    insert into public.room_members (room_id, user_id, role)
    values (target_room_id, auth.uid(), 'member')
    on conflict (room_id, user_id) do nothing;
    return target_room_id;
  end if;

  return null;
end;
$$;


-- EVENT MAKER 방 채팅
create table if not exists public.chat_messages (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  nickname text not null default '사용자',
  message text not null check (char_length(trim(message)) between 1 and 1000),
  created_at timestamptz not null default now()
);

alter table public.chat_messages enable row level security;

drop policy if exists "chat members can read" on public.chat_messages;
drop policy if exists "chat members can send" on public.chat_messages;

create policy "chat members can read"
on public.chat_messages
for select
to authenticated
using (public.is_room_member(room_id));

create policy "chat members can send"
on public.chat_messages
for insert
to authenticated
with check (
  user_id = auth.uid()
  and public.is_room_member(room_id)
);

create index if not exists chat_messages_room_created_idx
on public.chat_messages(room_id, created_at);

-- Supabase Realtime에서 채팅 INSERT를 받을 수 있도록 등록합니다.
do $$
begin
  alter publication supabase_realtime add table public.chat_messages;
exception
  when duplicate_object then null;
end $$;
