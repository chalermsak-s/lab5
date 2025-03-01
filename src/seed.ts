import { createEvents } from './db/createEvents';
import { PrismaClient } from '@prisma/client';
import { createParticipants } from './db/createParticipants';

const prisma = new PrismaClient();
async function main() {
  await createEvents();
  await createParticipants();
}

main()