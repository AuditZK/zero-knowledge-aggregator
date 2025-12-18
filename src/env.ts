// CRITICAL: This file MUST be imported FIRST before any other imports
// It loads .env and overrides system environment variables
import dotenv from 'dotenv';

// Override system env vars with local .env values
// This fixes the issue where system DATABASE_URL (Neon) overrides local .env (localhost:5436)
dotenv.config({ override: true });
