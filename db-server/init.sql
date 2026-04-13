INSERT INTO users (username, password_hash, role, failed_count, locked_until)
VALUES (
  'admin',
  'scrypt:32768:8:1$sVyeaB1aCaQH3aET$c58f774d2496f79713ca41807a5fde0f2c4bf98ab3f3084adb0d91defc6cf6569f109ee1d53fc5d9df2fb3be4fa7174b8a7bfa4918f0dfe1274a397e0ff127c9',
  'admin',
  0,
  NULL
);
