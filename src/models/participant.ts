import type { Event } from "./event";
export interface Participant{
    id:number
    name: string
    email: string
    events: Event[]
}