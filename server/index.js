import { config } from './config.js';
import { createApp } from './app.js';

const { server, db } = await createApp(config);
server.listen(config.port, () => {
  console.log(`TrustLens running on http://localhost:${config.port}  (database: ${db.driver})`);
  if (!config.isProd && config.jwtSecret === 'dev-only-secret-change-me') console.log('Using the development JWT secret. Set JWT_SECRET before deploying.');
  if (!config.adminEmail) console.log('Tip: set ADMIN_EMAIL and ADMIN_PASSWORD in .env to create a moderator account.');
});

for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => server.close(() => process.exit(0)));
