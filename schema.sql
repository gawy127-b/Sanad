CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 track TEXT NOT NULL CHECK(track IN ('thanaweya','bac2')),
 role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('student','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS resources (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 track TEXT NOT NULL CHECK(track IN ('thanaweya','bac2','both')),
 subject TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 kind TEXT NOT NULL DEFAULT 'ملخص',
 url TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS questions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 track TEXT NOT NULL CHECK(track IN ('thanaweya','bac2','both')),
 subject TEXT NOT NULL,
 prompt TEXT NOT NULL,
 options_json TEXT NOT NULL,
 correct_index INTEGER NOT NULL,
 explanation TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 subject TEXT NOT NULL,
 score INTEGER NOT NULL,
 total INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS study_tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL,
 subject TEXT DEFAULT '',
 due_date TEXT DEFAULT '',
 done INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contest_entries (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 points INTEGER NOT NULL DEFAULT 0,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contests (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 track TEXT NOT NULL DEFAULT 'both' CHECK(track IN ('thanaweya','bac2','both')),
 starts_at TEXT DEFAULT '',
 ends_at TEXT DEFAULT '',
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO resources(track,subject,title,description,kind) SELECT 'both','اللغة العربية','خريطة مراجعة المنهج','مساحة لإضافة ملخصات المنهج وروابط الشرح المعتمدة.','مراجعة' WHERE NOT EXISTS(SELECT 1 FROM resources);
INSERT INTO resources(track,subject,title,description,kind) VALUES('thanaweya','اللغة الإنجليزية','مراجعة المفردات والقواعد','أضف هنا ملفات الشرح والتدريبات الخاصة بتالتة ثانوي.','ملخص');
INSERT INTO resources(track,subject,title,description,kind) VALUES('bac2','الرياضيات','مراجعة المفاهيم الأساسية','أضف هنا موارد ومسارات تانية بكالوريا.','شرح');
INSERT INTO resources(track,subject,title,description,kind) VALUES('both','مهارات الدراسة','دليل المذاكرة الفعالة','إرشادات لتنظيم الوقت والاستعداد للامتحانات.','دليل');
INSERT INTO questions(track,subject,prompt,options_json,correct_index,explanation) SELECT 'both','مهارات عامة','ما أفضل طريقة لمتابعة خطة المذاكرة؟','["تحديد مهام واضحة ومراجعتها يوميًا","المذاكرة دون خطة","تأجيل كل المهام لنهاية الأسبوع","تجاهل فترات الراحة"]',0,'قسّم الهدف إلى مهام صغيرة، وتابع إنجازها باستمرار.' WHERE NOT EXISTS(SELECT 1 FROM questions);
CREATE UNIQUE INDEX IF NOT EXISTS one_sanad_admin ON users(role) WHERE role='admin';
