
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function createParticipants() {
  const participants = [
    {
      name: 'John Doe',
      email: 'john.doe@example.com',
    },
    {
      name: 'Jane Smith',
      email: 'jane.smith@example.com',
    },
    {
      name: 'Alice Johnson',
      email: 'alice.johnson@example.com',
    },
    {
      name: 'Bob Brown',
      email: 'bob.brown@example.com',
    },
    {
      name: 'Charlie Davis',
      email: 'charlie.davis@example.com',
    },
  ];

  for (const participant of participants) {
    await prisma.participant.create({
      data: participant,
    });
  }

    const resposneParticipants = await prisma.participant.findMany();
    const responseEvents = await prisma.event.findMany();
    
 
    addEvent(resposneParticipants[0].id, responseEvents[0].id)
    addEvent(resposneParticipants[0].id, responseEvents[1].id)
    addEvent(resposneParticipants[0].id, responseEvents[2].id)
    addEvent(resposneParticipants[1].id, responseEvents[3].id) 
    addEvent(resposneParticipants[1].id, responseEvents[4].id)
    addEvent(resposneParticipants[1].id, responseEvents[5].id)
    addEvent(resposneParticipants[2].id, responseEvents[0].id)
    addEvent(resposneParticipants[2].id, responseEvents[1].id)
    addEvent(resposneParticipants[3].id, responseEvents[2].id)
    addEvent(resposneParticipants[4].id, responseEvents[3].id)
    addEvent(resposneParticipants[4].id, responseEvents[4].id)
    addEvent(resposneParticipants[1].id, responseEvents[5].id)

    
  
}

async function addEvent(participantId: number, eventId: number) {
  await prisma.participant.update({
    where: { id: participantId },
    data: {
      events: {
        connect: {
          id: eventId,
        },
      },
    },
  });
}