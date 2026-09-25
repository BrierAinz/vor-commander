-- Lista de espera del acceso remoto de Vör Commander.
-- Una fila por correo (en minúsculas). Nunca se guarda la IP en claro: solo
-- un HMAC-SHA256 de ella, que sirve para limitar envíos, no para identificar.

CREATE TABLE IF NOT EXISTS waitlist (
  email       TEXT PRIMARY KEY NOT NULL,
  name        TEXT,
  use_case    TEXT,
  ip_hash     TEXT NOT NULL,
  user_agent  TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

-- Un registro por envío que llega a la verificación de Turnstile. Solo sirve
-- para el límite de 5 envíos por hora e IP; la función borra lo que tiene
-- más de un día.
CREATE TABLE IF NOT EXISTS waitlist_attempts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_hash     TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_waitlist_attempts_ip_time
  ON waitlist_attempts (ip_hash, created_at);
