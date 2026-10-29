import { config } from '../config.js';
import { createDb, migrate } from './index.js';

const db = await createDb(config);
await migrate(db);
console.log(`Schema is up to date (${db.driver}).`);
await db.close();
