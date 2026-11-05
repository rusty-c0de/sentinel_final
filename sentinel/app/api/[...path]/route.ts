import { env } from 'cloudflare:workers';
import { api } from '../../../lib/api';
export const dynamic='force-dynamic';
export const GET=(r:Request)=>api(r,env);
export const POST=(r:Request)=>api(r,env);
export const PATCH=(r:Request)=>api(r,env);
export const DELETE=(r:Request)=>api(r,env);
