# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Critical Non-Obvious Patterns

- **Dual storage system**: Public messages use JSON file (`data/messages.json`), private messages use MySQL database
- **CSRF protection**: All POST requests MUST include `csrf_token` from `$_SESSION['csrf_token']`
- **Custom Markdown parser**: Uses Parsedown with `setSafeMode(true)` and custom `customParse()` function that strips control characters
- **API authentication**: `db_api.php` uses `admin_password` from config as Bearer token (not standard user auth)
- **User settings storage**: Per-user settings stored as `data/settings_{user_id}.json` files (not in database)
- **Rate limiting**: Implemented via temporary JSON files `data/rate_{user_id}.json` (60-second windows)
- **Avatar system**: Default avatar is embedded SVG data URI when user has no avatar
- **Reply system**: Public messages store reply data inline in JSON, private messages use `reply_to_id` foreign key
- **Message recall**: Sets `recalled` flag to TRUE (doesn't delete), frontend filters recalled messages
- **Session regeneration**: Login calls `session_regenerate_id(true)` to prevent session fixation
- **Turnstile verification**: Registration requires Cloudflare Turnstile, keys hardcoded in `register.php` lines 8-9
- **Database connection**: Must use `get_db_connection()` from `db_connect.php`, NOT direct mysqli instantiation
- **Security validation**: File operations validate realpath to ensure files stay within `data/` directory
- **Markdown restrictions**: HTML blocks explicitly removed from Parsedown to prevent XSS (see `customParse()` line 47)

## Database Schema Quirks

- `users.avatar` defaults to `'default_avatar.png'` string, not NULL
- `private_messages.recalled` is BOOLEAN (not TINYINT as typical)
- Public messages don't have a database table (JSON file only)

## Testing

Run install.php once to set up database schema and directories. Delete install.php after setup.