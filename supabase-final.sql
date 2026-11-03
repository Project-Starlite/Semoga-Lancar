-- =====================================================================
--  ABSENSI & REPORT TEKNISI — SKEMA LENGKAP SUPABASE
--  Cara pakai: Supabase → SQL Editor → + (query baru) → pilihan "Database"
--  → tempel SELURUH isi file ini → Run.
--  Aman dijalankan ulang. Menjalankan ulang akan MENGHAPUS data absensi & report.
-- =====================================================================

create extension if not exists pgcrypto;
set search_path = public, extensions;

-- ---------------------------------------------------------------------
-- 1. BERSIHKAN VERSI LAMA
-- ---------------------------------------------------------------------
drop table if exists public.laporan cascade;
drop table if exists public.absensi cascade;
drop table if exists public.sesi cascade;
drop table if exists public.teknisi cascade;
drop function if exists public.login(text, text);
drop function if exists public.sesi_info(uuid);
drop function if exists public.logout(uuid);
drop function if exists public.absen(uuid, text, float8, float8, float8, text);
drop function if exists public.kirim_laporan(uuid, text, text, text, text, text, text, numeric, text, float8, float8, float8, text[]);
drop function if exists public.daftar_teknisi();

-- ---------------------------------------------------------------------
-- 2. TABEL
-- ---------------------------------------------------------------------
create table if not exists public.lokasi (
  id          uuid primary key default gen_random_uuid(),
  nama        text not null,
  lat         double precision not null check (lat between -90 and 90),
  lng         double precision not null check (lng between -180 and 180),
  radius      integer not null default 100 check (radius between 10 and 5000),
  created_at  timestamptz not null default now()
);

create table if not exists public.pengaturan (
  id               integer primary key default 1 check (id = 1),
  jam_masuk        time not null default '08:00',
  jam_pulang       time not null default '17:00',
  toleransi_menit  integer not null default 15 check (toleransi_menit between 0 and 240),
  akurasi_maks     integer not null default 100 check (akurasi_maks between 10 and 1000)
);
insert into public.pengaturan (id) values (1) on conflict (id) do nothing;

-- Akun teknisi (password disimpan ter-enkripsi bcrypt)
create table public.teknisi (
  id             uuid primary key default gen_random_uuid(),
  username       text not null,
  nama           text not null,
  password_hash  text not null,
  aktif          boolean not null default true,
  created_at     timestamptz not null default now()
);
create unique index teknisi_username_unik on public.teknisi (lower(username));

-- Sesi login (token disimpan di HP teknisi, berlaku 30 hari)
create table public.sesi (
  token       uuid primary key default gen_random_uuid(),
  teknisi_id  uuid not null references public.teknisi(id) on delete cascade,
  dibuat      timestamptz not null default now(),
  berakhir    timestamptz not null default now() + interval '30 days'
);

create table public.absensi (
  id            uuid primary key default gen_random_uuid(),
  teknisi_id    uuid not null references public.teknisi(id) on delete cascade,
  teknisi       text not null,
  tipe          text not null check (tipe in ('MASUK','PULANG')),
  waktu         timestamptz not null default now(),
  tanggal       date not null default ((now() at time zone 'Asia/Jakarta')::date),
  status        text not null,
  lat           double precision not null,
  lng           double precision not null,
  akurasi       double precision,
  lokasi_nama   text,
  jarak         integer,
  foto_path     text not null,
  unique (teknisi_id, tanggal, tipe)
);
create index absensi_tanggal_idx on public.absensi (tanggal);

create table public.laporan (
  id              uuid primary key default gen_random_uuid(),
  teknisi_id      uuid not null references public.teknisi(id) on delete cascade,
  teknisi         text not null,
  waktu           timestamptz not null default now(),
  tanggal         date not null default ((now() at time zone 'Asia/Jakarta')::date),
  nama_pelanggan  text not null,
  id_pelanggan    text not null,
  sn_ont          text not null,
  odc             text not null,
  odp             text not null,
  port            text not null,
  panjang_kabel   numeric(8,1) not null check (panjang_kabel >= 0 and panjang_kabel <= 100000),
  stasiun         text not null,
  lat             double precision,
  lng             double precision,
  akurasi         double precision,
  foto_paths      text[] not null default '{}'
);
create index laporan_tanggal_idx on public.laporan (tanggal);

-- ---------------------------------------------------------------------
-- 3. AKUN TEKNISI
--    Untuk menambah teknisi: salin satu baris, ubah username & password.
-- ---------------------------------------------------------------------
insert into public.teknisi (username, nama, password_hash) values
  ('Purwanto',  'Purwanto',  crypt('Purwanto123!',  gen_salt('bf'))),
  ('Hadibima',  'Hadibima',  crypt('Hadi123!',      gen_salt('bf'))),
  ('Alfarizki', 'Alfarizki', crypt('Alfa123',       gen_salt('bf'))),
  ('Faisal',    'Faisal',    crypt('Ical123!',      gen_salt('bf'))),
  ('Eko',       'Eko',       crypt('Kasbianto123!', gen_salt('bf'))),
  ('Sutrisno',  'Sutrisno',  crypt('Trisno123!',    gen_salt('bf'))),
  ('Putra',     'Putra',     crypt('Putra123!',     gen_salt('bf'))),
  ('Yogi',      'Yogi',      crypt('Yogi123!',      gen_salt('bf')));

-- ---------------------------------------------------------------------
-- 4. FUNGSI (semua penulisan data lewat fungsi ini; dicek di server)
-- ---------------------------------------------------------------------
create or replace function public.jarak_m(lat1 float8, lng1 float8, lat2 float8, lng2 float8)
returns float8 language sql immutable as $$
  select 2 * 6371000 * asin(sqrt(
    power(sin(radians(lat2 - lat1) / 2), 2) +
    cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2)));
$$;

-- Teknisi dari token; error jika token tidak berlaku
create or replace function public._teknisi_dari_token(p_token uuid)
returns public.teknisi language plpgsql stable security definer set search_path = public, extensions as $$
declare t public.teknisi;
begin
  select k.* into t from public.sesi s join public.teknisi k on k.id = s.teknisi_id
   where s.token = p_token and s.berakhir > now() and k.aktif;
  if not found then
    raise exception 'Sesi berakhir. Silakan login lagi.';
  end if;
  return t;
end $$;

create or replace function public.login(p_username text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare t public.teknisi; tok uuid;
begin
  select * into t from public.teknisi where lower(username) = lower(trim(p_username));
  if not found or t.password_hash <> crypt(coalesce(p_password, ''), t.password_hash) then
    raise exception 'Username atau password salah.';
  end if;
  if not t.aktif then
    raise exception 'Akun dinonaktifkan. Hubungi admin.';
  end if;
  delete from public.sesi where berakhir < now();
  insert into public.sesi (teknisi_id) values (t.id) returning token into tok;
  return json_build_object('token', tok, 'nama', t.nama);
end $$;

create or replace function public.sesi_info(p_token uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare t public.teknisi;
begin
  t := public._teknisi_dari_token(p_token);
  return json_build_object('nama', t.nama);
end $$;

create or replace function public.logout(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from public.sesi where token = p_token;
$$;

create or replace function public.daftar_teknisi()
returns table (nama text) language sql stable security definer set search_path = public as $$
  select nama from public.teknisi where aktif order by nama;
$$;

create or replace function public.absen(p_token uuid, p_tipe text, p_lat float8, p_lng float8, p_akurasi float8, p_foto text)
returns public.absensi language plpgsql security definer set search_path = public, extensions as $$
declare
  t public.teknisi; s public.pengaturan; l record; r public.absensi;
  best_nama text; best_jarak float8; best_rad integer; d float8;
  tgl date := (now() at time zone 'Asia/Jakarta')::date;
  jam time := (now() at time zone 'Asia/Jakarta')::time;
begin
  t := public._teknisi_dari_token(p_token);
  select * into s from public.pengaturan where id = 1;
  if p_tipe not in ('MASUK','PULANG') then raise exception 'Tipe absen tidak valid.'; end if;
  if p_lat is null or p_lng is null then raise exception 'Lokasi GPS tidak terbaca. Aktifkan GPS lalu coba lagi.'; end if;
  if p_akurasi is not null and p_akurasi > s.akurasi_maks then
    raise exception 'Akurasi GPS ±% m melebihi batas ±% m. Pindah ke area terbuka.', round(p_akurasi), s.akurasi_maks;
  end if;
  for l in select * from public.lokasi loop
    d := public.jarak_m(p_lat, p_lng, l.lat, l.lng);
    if best_nama is null or d - l.radius < best_jarak - best_rad then
      best_nama := l.nama; best_jarak := d; best_rad := l.radius;
    end if;
  end loop;
  if best_nama is null then raise exception 'Belum ada lokasi absen. Hubungi admin.'; end if;
  if best_jarak > best_rad then
    raise exception 'Di luar area absen: % m dari % (radius % m).', round(best_jarak), best_nama, best_rad;
  end if;
  if p_foto is null or p_foto not like 'absen/%' then raise exception 'Foto selfie wajib dilampirkan.'; end if;

  if p_tipe = 'MASUK' then
    if exists (select 1 from public.absensi where teknisi_id = t.id and tanggal = tgl and tipe = 'MASUK') then
      raise exception 'Anda sudah absen masuk hari ini.';
    end if;
  else
    if not exists (select 1 from public.absensi where teknisi_id = t.id and tanggal = tgl and tipe = 'MASUK') then
      raise exception 'Absen masuk dulu sebelum absen pulang.';
    end if;
    if exists (select 1 from public.absensi where teknisi_id = t.id and tanggal = tgl and tipe = 'PULANG') then
      raise exception 'Anda sudah absen pulang hari ini.';
    end if;
  end if;

  insert into public.absensi (teknisi_id, teknisi, tipe, tanggal, status, lat, lng, akurasi, lokasi_nama, jarak, foto_path)
  values (t.id, t.nama, p_tipe, tgl,
          case when p_tipe = 'MASUK' then
                 case when jam > s.jam_masuk + make_interval(mins => s.toleransi_menit) then 'Terlambat' else 'Tepat Waktu' end
               else case when jam < s.jam_pulang then 'Pulang Cepat' else 'Tepat Waktu' end end,
          p_lat, p_lng, p_akurasi, best_nama, round(best_jarak), p_foto)
  returning * into r;
  return r;
end $$;

create or replace function public.kirim_laporan(
  p_token uuid, p_nama_pelanggan text, p_id_pelanggan text, p_sn_ont text, p_odc text, p_odp text,
  p_port text, p_panjang_kabel numeric, p_stasiun text, p_lat float8, p_lng float8, p_akurasi float8, p_foto_paths text[])
returns public.laporan language plpgsql security definer set search_path = public, extensions as $$
declare t public.teknisi; r public.laporan; tgl date := (now() at time zone 'Asia/Jakarta')::date;
  wajib text[] := array[p_nama_pelanggan, p_id_pelanggan, p_sn_ont, p_odc, p_odp, p_port, p_stasiun];
begin
  t := public._teknisi_dari_token(p_token);
  if not exists (select 1 from public.absensi where teknisi_id = t.id and tanggal = tgl and tipe = 'MASUK') then
    raise exception 'Absen masuk dulu sebelum mengirim report.';
  end if;
  if exists (select 1 from unnest(wajib) v where coalesce(trim(v), '') = '') or p_panjang_kabel is null then
    raise exception 'Semua isian report wajib diisi. Tulis "-" jika tidak ada.';
  end if;
  if exists (select 1 from unnest(wajib) v where char_length(v) > 150) then
    raise exception 'Isian terlalu panjang.';
  end if;
  if coalesce(cardinality(p_foto_paths), 0) = 0 then raise exception 'Lampirkan minimal 1 foto.'; end if;
  if cardinality(p_foto_paths) > 8 or exists (select 1 from unnest(p_foto_paths) f where f not like 'laporan/%') then
    raise exception 'Foto report tidak valid.';
  end if;
  insert into public.laporan (teknisi_id, teknisi, tanggal, nama_pelanggan, id_pelanggan, sn_ont, odc, odp, port,
                              panjang_kabel, stasiun, lat, lng, akurasi, foto_paths)
  values (t.id, t.nama, tgl, trim(p_nama_pelanggan), trim(p_id_pelanggan), trim(p_sn_ont), trim(p_odc), trim(p_odp),
          trim(p_port), p_panjang_kabel, trim(p_stasiun), p_lat, p_lng, p_akurasi, p_foto_paths)
  returning * into r;
  return r;
end $$;

-- Hanya fungsi publik ini yang boleh dipanggil dari aplikasi
revoke all on function public._teknisi_dari_token(uuid) from public, anon, authenticated;
grant execute on function public.login(text, text) to anon, authenticated;
grant execute on function public.sesi_info(uuid) to anon, authenticated;
grant execute on function public.logout(uuid) to anon, authenticated;
grant execute on function public.daftar_teknisi() to anon, authenticated;
grant execute on function public.absen(uuid, text, float8, float8, float8, text) to anon, authenticated;
grant execute on function public.kirim_laporan(uuid, text, text, text, text, text, text, numeric, text, float8, float8, float8, text[]) to anon, authenticated;

-- ---------------------------------------------------------------------
-- 5. KEAMANAN TABEL
--    Dashboard boleh membaca absensi, report, lokasi, pengaturan.
--    Akun & sesi tidak bisa dibaca dari luar. Tidak ada yang bisa
--    mengubah/menghapus data dari aplikasi.
-- ---------------------------------------------------------------------
alter table public.lokasi     enable row level security;
alter table public.pengaturan enable row level security;
alter table public.teknisi    enable row level security;
alter table public.sesi       enable row level security;
alter table public.absensi    enable row level security;
alter table public.laporan    enable row level security;

drop policy if exists "lokasi_baca"     on public.lokasi;
drop policy if exists "lokasi_admin"    on public.lokasi;
drop policy if exists "pengaturan_baca" on public.pengaturan;
drop policy if exists "pengaturan_ubah" on public.pengaturan;
create policy "lokasi_baca"     on public.lokasi     for select to anon, authenticated using (true);
create policy "pengaturan_baca" on public.pengaturan for select to anon, authenticated using (true);
create policy "absensi_baca"    on public.absensi    for select to anon, authenticated using (true);
create policy "laporan_baca"    on public.laporan    for select to anon, authenticated using (true);

-- ---------------------------------------------------------------------
-- 6. FOTO (bucket publik "foto", hanya JPEG, maks 2 MB)
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('foto', 'foto', true, 2097152, array['image/jpeg'])
on conflict (id) do update set public = true, file_size_limit = 2097152, allowed_mime_types = array['image/jpeg'];

drop policy if exists "foto_upload" on storage.objects;
drop policy if exists "foto_baca"   on storage.objects;
drop policy if exists "foto_hapus"  on storage.objects;
drop policy if exists "foto_publik_upload" on storage.objects;
create policy "foto_publik_upload" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'foto' and (name like 'absen/%' or name like 'laporan/%'));

-- ---------------------------------------------------------------------
-- 7. REALTIME (dashboard ter-update otomatis)
-- ---------------------------------------------------------------------
do $$ begin alter publication supabase_realtime add table public.absensi;
exception when duplicate_object then null; when undefined_object then null; end $$;
do $$ begin alter publication supabase_realtime add table public.laporan;
exception when duplicate_object then null; when undefined_object then null; end $$;

-- =====================================================================
-- PERINTAH BERGUNA (jalankan terpisah bila perlu)
--
-- Tambah lokasi absen (koordinat dari dashboard tab "Lokasi"):
--   insert into public.lokasi (nama, lat, lng, radius) values ('Stasiun Pabuaran', -6.5715, 107.7587, 200);
--
-- Ganti password teknisi:
--   update public.teknisi set password_hash = crypt('PasswordBaru123!', gen_salt('bf')) where username = 'Yogi';
--
-- Tambah teknisi baru:
--   insert into public.teknisi (username, nama, password_hash) values ('Budi', 'Budi', crypt('Budi123!', gen_salt('bf')));
--
-- Nonaktifkan teknisi:
--   update public.teknisi set aktif = false where username = 'Yogi';
--
-- Ubah jam kerja:
--   update public.pengaturan set jam_masuk = '08:00', jam_pulang = '17:00', toleransi_menit = 15 where id = 1;
-- =====================================================================
