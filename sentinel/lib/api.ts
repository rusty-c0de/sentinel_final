import {APPROVED_INSTALLATIONS,installationById,resolveInstallation,dummyPocEmail} from './installations';
import {parseLog} from './parser';
import { getThreatIntel } from './threat-intel';
import { ingestLog } from './ingest';
import { analyzeObservations } from './analysis';
import { countryLocation,normalizeIp,validCoordinates } from './geo';
import type { Installation,Observation,SourceLocation,Workspace } from './types';
import {buildCommanderOverview,type CommanderDocument} from './commander';
import {reportLogBriefs} from './report-evidence';
import {HOME_INSTALLATION_ID,HOME_MEMBERSHIP} from './home-base';
import {buildAttackMetadata,readAttackMetadata} from './attack-metadata';
import {buildExposureAssessment} from './exposure';
// Server-only password gate. No passwords or session tokens are returned in JSON.
function cookieName(r:Request){return import.meta.env.DEV&&new URL(r.url).protocol==='http:'?'sentinel_preview':'__Host-sentinel';}
const SESSION_SECONDS=8*60*60;
const COMMANDER_SESSION_SECONDS=60*60;
class HttpError extends Error {constructor(public status:number,message:string){super(message);}}
function json(data:unknown,status=200,extra:Record<string,string>={}){return Response.json(data,{status,headers:{'Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff',...extra}});}
async function digest(value:string){const d=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));return [...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,'0')).join('');}
function cookieToken(r:Request){const name=cookieName(r);return (r.headers.get('cookie')??'').split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1)??'';}
function sessionCookie(r:Request,value:string,maxAge:number){const secure=cookieName(r).startsWith('__Host-');return `${cookieName(r)}=${value}; Path=/; HttpOnly; ${secure?'Secure; ':''}SameSite=Strict; Max-Age=${maxAge}`;}
async function authorized(r:Request,e:Cloudflare.Env){const token=cookieToken(r);if(!e.SITE_PASSWORD||!e.DB||!/^[a-f0-9]{64}$/.test(token))return false;const hash=await digest(token+e.SITE_PASSWORD);return !!await e.DB.prepare('SELECT token_hash FROM sessions WHERE token_hash=? AND expires_at>?').bind(hash,Date.now()).first();}
function commanderCookieName(r:Request){return cookieName(r)==='sentinel_preview'?'sentinel_commander_preview':'__Host-sentinel-commander';}
function commanderToken(r:Request){const name=commanderCookieName(r);return (r.headers.get('cookie')??'').split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1)??'';}
function commanderCookie(r:Request,value:string,maxAge:number){return `${commanderCookieName(r)}=${value}; Path=/; HttpOnly; ${commanderCookieName(r).startsWith('__Host-')?'Secure; ':''}SameSite=Strict; Max-Age=${maxAge}`;}
async function commanderAuthorized(r:Request,e:Cloudflare.Env){
 const token=commanderToken(r);if(!e.COMMANDER_PASSWORD||!e.DB||!/^[a-f0-9]{64}$/.test(token))return false;
 return !!await e.DB.prepare('SELECT token_hash FROM commander_sessions WHERE token_hash=? AND workspace_hash=? AND expires_at>?').bind(await digest(token+e.COMMANDER_PASSWORD),await digest(cookieToken(r)+e.SITE_PASSWORD),Date.now()).first();
}
function mutationOrigin(r:Request){const origin=r.headers.get('Origin');if(!origin||origin!==new URL(r.url).origin)throw new HttpError(403,'Please submit from this website.');}
async function body(r:Request){if(!r.headers.get('content-type')?.includes('application/json'))throw new HttpError(415,'Expected a JSON submission.');const reader=r.body?.getReader();if(!reader)throw new HttpError(400,'Missing submission.');const parts:Uint8Array[]=[];let size=0;while(true){const{value,done}=await reader.read();if(done)break;size+=value.length;if(size>650000){await reader.cancel();throw new HttpError(413,'Submission is too large. Logs must be under 500 KB.');}parts.push(value);}const merged=new Uint8Array(size);let offset=0;for(const p of parts){merged.set(p,offset);offset+=p.length;}try{const value=JSON.parse(new TextDecoder().decode(merged));if(!value||typeof value!=='object'||Array.isArray(value))throw Error();return value;}catch{throw new HttpError(400,'Invalid submission.');}}
function field(v:unknown,max:number,required=false){if(typeof v!=='string'){if(required)throw new HttpError(400,'Please complete all required fields.');return '';}const s=v.trim();if(s.length>max)throw new HttpError(400,`A field exceeds ${max} characters.`);if(required&&!s)throw new HttpError(400,'Please complete all required fields.');return s;}
function contactFields(data:any,prior?:Installation){
 const contactName=field(data.contactName??prior?.contactName,120),contactEmail=field(data.contactEmail??prior?.contactEmail,200),contactPhone=field(data.contactPhone??prior?.contactPhone,80);
 if(contactEmail&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail))throw new HttpError(400,'Enter a valid contact email.');
 return {contactName,contactEmail,contactPhone};
}
const directoryQuery='SELECT id,name,region,lat,lng,contact_name AS contactName,contact_email AS contactEmail,contact_phone AS contactPhone,created_at AS createdAt,updated_at AS updatedAt FROM installations';
function storedInstallation(row:Pick<Installation,'id'|'name'>){return installationById(row.id)??resolveInstallation(row.name);}
async function fixedDirectory(db:D1Database){
 const prior=(await db.prepare(directoryQuery).all<Installation>()).results,now=new Date().toISOString(),missing:Installation[]=[];
 for(const base of APPROVED_INSTALLATIONS){if(prior.some(row=>row.id===base.id))continue;const legacy=prior.filter(row=>storedInstallation(row)?.id===base.id).sort((a,b)=>b.updatedAt.localeCompare(a.updatedAt))[0];missing.push({id:base.id,name:base.name,region:base.region,lat:base.lat,lng:base.lng,contactName:legacy?.contactName??'',contactEmail:legacy?.contactEmail??'',contactPhone:legacy?.contactPhone??'',createdAt:legacy?.createdAt??now,updatedAt:legacy?.updatedAt??now});}
 if(missing.length)await db.batch(missing.map(base=>db.prepare('INSERT OR IGNORE INTO installations (id,name,region,lat,lng,contact_name,contact_email,contact_phone,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(base.id,base.name,base.region,base.lat,base.lng,base.contactName,base.contactEmail,base.contactPhone,base.createdAt,base.updatedAt)));
 // Read-only projection preserves legacy records while keeping the active directory fixed.
 return [...prior,...missing];
}
function reportInstallation(data:any){
 for(const key of ['siteId','name','rawLog'])if(data[key]!==undefined&&typeof data[key]!=='string')throw new HttpError(400,'Installation identifiers and source logs must be text.');
 if(data.includeIncident!==undefined&&typeof data.includeIncident!=='boolean')throw new HttpError(400,'Invalid report mode.');
 const id=field(data.siteId,80),name=field(data.name,120);const base=id?installationById(id):resolveInstallation(name);
 if(!base)throw new HttpError(400,'Choose a target installation from the approved U.S. military base list.');
 if(name&&resolveInstallation(name)?.id!==base.id)throw new HttpError(400,'The report installation name does not match the approved target.');
 for(const [key,value]of [['lat',base.lat],['lng',base.lng]] as const)if(Object.hasOwn(data,key)&&(data[key]===''||data[key]===null||Number(data[key])!==value))throw new HttpError(400,'Installation map locations are fixed and cannot be changed.');
 if(data.region!==undefined&&data.region!==base.region)throw new HttpError(400,'Installation regions are fixed and cannot be changed.');
 if(data.includeIncident===false||data.locationOnly)throw new HttpError(400,'Installation creation is disabled. Submit an incident report for an approved base.');
 for(const key of ['targetSiteIds','target_site_ids','targets','targetInstallation','target_installation','installation','installation_name','installationId','installation_id','targetSite','target_site','targetSiteId','target_site_id','destinationInstallation','destination_installation','destinationSite','destination_site','site','site_name','siteName'])if(Object.hasOwn(data,key))throw new HttpError(400,'Choose one approved primary installation; additional targets are determined from validated log evidence.');
 return base;
}
const severities=['low','medium','high','critical'],statuses=['reported','investigating','resolved'];
async function workspaceData(db:D1Database):Promise<Workspace>{
  const rows=await fixedDirectory(db),canonical=new Map(rows.flatMap(row=>{const base=storedInstallation(row);return base?[[row.id,base.id] as const]:[];})),allowed=JSON.stringify([...canonical.keys()]);
  const [i,o,l,c,links]=await db.batch([
   db.prepare('SELECT id,site_id AS siteId,title,summary,severity,status,log_key IS NOT NULL AS hasLog,file_name AS fileName,attack_metadata AS attackMetadata,created_at AS createdAt,updated_at AS updatedAt FROM incidents WHERE site_id IN (SELECT value FROM json_each(?)) ORDER BY created_at DESC').bind(allowed),
   db.prepare('SELECT o.id,o.incident_id AS incidentId,o.site_id AS siteId,o.source_ip AS sourceIp,o.target_ip AS targetIp,o.target_port AS targetPort,o.protocol,o.username,o.event_type AS eventType,o.outcome,o.occurred_at AS occurredAt,o.source_label AS sourceLabel,o.source_lat AS sourceLat,o.source_lng AS sourceLng,o.precision,o.line_number AS lineNumber,o.created_at AS createdAt FROM observations o JOIN incidents i ON i.id=o.incident_id WHERE o.site_id IN (SELECT value FROM json_each(?)) AND i.site_id IN (SELECT value FROM json_each(?)) ORDER BY o.created_at DESC,o.rowid DESC LIMIT 5000').bind(allowed,allowed),
   db.prepare('SELECT source_ip AS sourceIp,label,lat,lng,precision,updated_at AS updatedAt FROM source_locations'),
   db.prepare('SELECT COUNT(*) AS total FROM observations o JOIN incidents i ON i.id=o.incident_id WHERE o.site_id IN (SELECT value FROM json_each(?)) AND i.site_id IN (SELECT value FROM json_each(?))').bind(allowed,allowed),
   db.prepare('SELECT o.incident_id AS incidentId,o.site_id AS siteId FROM observations o JOIN incidents i ON i.id=o.incident_id WHERE o.site_id IN (SELECT value FROM json_each(?)) AND i.site_id IN (SELECT value FROM json_each(?)) GROUP BY o.incident_id,o.site_id').bind(allowed,allowed)
  ]);
  const observations=(o.results as unknown as Observation[]).map(event=>({...event,siteId:canonical.get(event.siteId)!})),locations=l.results as unknown as SourceLocation[];
  const logBriefs=reportLogBriefs(observations,locations);
  const sites=APPROVED_INSTALLATIONS.map(base=>{const row=rows.find(row=>row.id===base.id)!;return {...row,id:base.id,name:base.name,region:base.region,lat:base.lat,lng:base.lng,contactEmail:row.contactEmail||dummyPocEmail(base.id)};});
  const workspace:Workspace={membership:HOME_MEMBERSHIP,sites,incidents:i.results.map((v:any)=>({...v,siteId:canonical.get(v.siteId),attackMetadata:readAttackMetadata(v.attackMetadata,v.title,v.summary,canonical.get(v.siteId)!),hasLog:!!v.hasLog,logBriefs:logBriefs.get(v.id)??[],targetSiteIds:[...new Set([canonical.get(v.siteId),...links.results.filter((x:any)=>x.incidentId===v.id).map((x:any)=>canonical.get(x.siteId))])]})),analysis:analyzeObservations(observations,locations,Number((c.results[0] as any)?.total??0)),updatedAt:new Date().toISOString()};
  workspace.exposure=buildExposureAssessment(workspace,HOME_INSTALLATION_ID,new Date(),observations);
  return workspace;
}
async function handle(r:Request,e:Cloudflare.Env):Promise<Response>{
 const path=new URL(r.url).pathname,method=r.method;
 if(!e.DB||!e.SITE_PASSWORD)throw new HttpError(503,'Workspace setup is incomplete. Please contact the site owner.');
 if(method!=='GET'&&method!=='HEAD')mutationOrigin(r);
 if(path==='/api/session'&&method==='GET'){const authenticated=await authorized(r,e);return json({authenticated,...(authenticated?{membership:HOME_MEMBERSHIP,role:'operator'}:{})});}
 if(path==='/api/login'&&method==='POST'){
  const data=await body(r);if(Object.keys(data).some(key=>key!=='password'))throw new HttpError(400,'The home installation is assigned by the server.');const password=typeof data.password==='string'?data.password:'';if(password.length>256)throw new HttpError(400,'Invalid password.');
  const now=Date.now(),bucket=Math.floor(now/900000);const key=await digest((r.headers.get('cf-connecting-ip')??'unknown')+':'+bucket+':'+e.SITE_PASSWORD);
  const limit=await e.DB.prepare('INSERT INTO login_limits (key,attempts,expires_at) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=attempts+1 RETURNING attempts').bind(key,now+900000).first<{attempts:number}>();
  if((limit?.attempts??99)>10)throw new HttpError(429,'Too many attempts. Please try again in 15 minutes.');
  const a=await digest(password),b=await digest(e.SITE_PASSWORD);let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);if(diff)throw new HttpError(401,'Incorrect password. Please try again.');
  const token=[...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,'0')).join('');
  await e.DB.batch([e.DB.prepare('INSERT INTO sessions (token_hash,expires_at) VALUES (?,?)').bind(await digest(token+e.SITE_PASSWORD),now+SESSION_SECONDS*1000),e.DB.prepare('DELETE FROM sessions WHERE expires_at<?').bind(now),e.DB.prepare('DELETE FROM login_limits WHERE key=? OR expires_at<?').bind(key,now)]);
  return json({ok:true},200,{'Set-Cookie':sessionCookie(r,token,SESSION_SECONDS)});
 }
 if(!await authorized(r,e))throw new HttpError(401,'Your session has ended. Please unlock the workspace.');
 if(path==='/api/membership'){if(method!=='GET')throw new HttpError(405,'Your single home installation is assigned by the server.');return json({membership:HOME_MEMBERSHIP,role:'operator'});}
 if(path==='/api/threat-intel'&&method==='GET')return json(await getThreatIntel(e.DB));
 if(path==='/api/logout'&&method==='POST'){
  const workspaceHash=await digest(cookieToken(r)+e.SITE_PASSWORD);
  await e.DB.batch([e.DB.prepare('DELETE FROM commander_sessions WHERE workspace_hash=?').bind(workspaceHash),e.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(workspaceHash)]);
  const response=json({ok:true},200,{'Set-Cookie':sessionCookie(r,'',0)});response.headers.append('Set-Cookie',commanderCookie(r,'',0));return response;
 }
 if(path.startsWith('/api/commander/')){
  if(!e.COMMANDER_PASSWORD)throw new HttpError(503,'Commander access is not configured. Please contact the site owner.');
  if(path==='/api/commander/session'&&method==='GET'){const authenticated=await commanderAuthorized(r,e);return json({authenticated,...(authenticated?{membership:HOME_MEMBERSHIP,role:'commander'}:{})});}
  if(path==='/api/commander/login'&&method==='POST'){
   const data=await body(r);if(Object.keys(data).some(key=>key!=='password'))throw new HttpError(400,'Commander access inherits your assigned installation.');const password=typeof data.password==='string'?data.password:'';
   if(password.length>256)throw new HttpError(400,'Invalid commander password.');
   const now=Date.now(),key=await digest('commander:'+(r.headers.get('cf-connecting-ip')??'unknown')+':'+Math.floor(now/900000)+':'+e.COMMANDER_PASSWORD);
   const limit=await e.DB.prepare('INSERT INTO login_limits (key,attempts,expires_at) VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=attempts+1 RETURNING attempts').bind(key,now+900000).first<{attempts:number}>();
   if((limit?.attempts??99)>10)throw new HttpError(429,'Too many commander password attempts. Please try again in 15 minutes.');
   const a=await digest(password),b=await digest(e.COMMANDER_PASSWORD);let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);if(diff)throw new HttpError(403,'Incorrect commander password. Please try again.');
   const workspaceHash=await digest(cookieToken(r)+e.SITE_PASSWORD),workspaceSession=await e.DB.prepare('SELECT expires_at FROM sessions WHERE token_hash=?').bind(workspaceHash).first<{expires_at:number}>();
   if(!workspaceSession||workspaceSession.expires_at<=now)throw new HttpError(401,'Your workspace session has ended.');
   const expires=Math.min(now+COMMANDER_SESSION_SECONDS*1000,workspaceSession.expires_at),token=[...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,'0')).join('');
   const prior=commanderToken(r),statements=[e.DB.prepare('INSERT INTO commander_sessions (token_hash,workspace_hash,expires_at) VALUES (?,?,?)').bind(await digest(token+e.COMMANDER_PASSWORD),workspaceHash,expires),e.DB.prepare('DELETE FROM commander_sessions WHERE expires_at<?').bind(now),e.DB.prepare('DELETE FROM login_limits WHERE key=? OR expires_at<?').bind(key,now)];
   if(/^[a-f0-9]{64}$/.test(prior))statements.push(e.DB.prepare('DELETE FROM commander_sessions WHERE token_hash=? AND workspace_hash=?').bind(await digest(prior+e.COMMANDER_PASSWORD),workspaceHash));
   await e.DB.batch(statements);return json({ok:true},200,{'Set-Cookie':commanderCookie(r,token,Math.floor((expires-now)/1000))});
  }
  if(path==='/api/commander/logout'&&method==='POST'){
   await e.DB.prepare('DELETE FROM commander_sessions WHERE token_hash=? AND workspace_hash=?').bind(await digest(commanderToken(r)+e.COMMANDER_PASSWORD),await digest(cookieToken(r)+e.SITE_PASSWORD)).run();return json({ok:true},200,{'Set-Cookie':commanderCookie(r,'',0)});
  }
  if(!await commanderAuthorized(r,e))throw new HttpError(403,'Commander access is locked. Enter the commander password to continue.');
  if(path==='/api/commander/overview'&&method==='GET'){
   const workspace=await workspaceData(e.DB),documents=await e.DB.prepare('SELECT id,kind,incident_id AS incidentId,title,body,status,revision,created_at AS createdAt,updated_at AS updatedAt FROM commander_documents ORDER BY updated_at DESC LIMIT 200').all<CommanderDocument>();
   return json(buildCommanderOverview(workspace,documents.results));
  }
  const documentMatch=path.match(/^\/api\/commander\/documents\/([a-f0-9-]{36})$/);
  if((path==='/api/commander/documents'&&method==='POST')||(documentMatch&&method==='PATCH')){
   const data=await body(r);if(Object.keys(data).some(key=>!['kind','title','body','status','incidentId','revision'].includes(key)))throw new HttpError(400,'Invalid commander document fields.');
   const kind=field(data.kind,10,true),title=field(data.title,180,true),content=field(data.body,20000,true),status=field(data.status,20,true);
   if(!['aar','coa'].includes(kind)||!['draft','reviewed'].includes(status))throw new HttpError(400,'Choose a valid document type and review status.');
   if(data.incidentId!==undefined&&data.incidentId!==null&&typeof data.incidentId!=='string')throw new HttpError(400,'Invalid report reference.');
   const incidentId=field(data.incidentId,80)||null,workspace=await workspaceData(e.DB);
   if(incidentId&&!workspace.incidents.some(i=>i.id===incidentId&&(i.siteId===HOME_INSTALLATION_ID||i.targetSiteIds?.includes(HOME_INSTALLATION_ID))))throw new HttpError(400,'Choose a report for your assigned installation.');
   const now=new Date().toISOString(),id=documentMatch?.[1]??crypto.randomUUID();
   if(documentMatch){
    if(!Number.isInteger(data.revision)||data.revision<1)throw new HttpError(400,'A current document revision is required.');
    const prior=await e.DB.prepare('SELECT kind,incident_id AS incidentId FROM commander_documents WHERE id=?').bind(id).first<{kind:string;incidentId:string|null}>();if(!prior)throw new HttpError(404,'Commander document not found.');if(prior.incidentId&&!workspace.incidents.some(i=>i.id===prior.incidentId&&(i.siteId===HOME_INSTALLATION_ID||i.targetSiteIds?.includes(HOME_INSTALLATION_ID))))throw new HttpError(403,'This document is outside your assigned installation.');if(prior.kind!==kind)throw new HttpError(400,'The document type cannot be changed.');
    const result=await e.DB.prepare('UPDATE commander_documents SET title=?,body=?,status=?,incident_id=?,updated_at=?,revision=revision+1 WHERE id=? AND revision=?').bind(title,content,status,incidentId,now,id,data.revision).run();if(!result.meta.changes)throw new HttpError(409,'This document changed in another session. Refresh and reopen it before editing.');
   }else await e.DB.prepare('INSERT INTO commander_documents (id,kind,incident_id,title,body,status,revision,created_at,updated_at) VALUES (?,?,?,?,?,?,1,?,?)').bind(id,kind,incidentId,title,content,status,now,now).run();
   return json({ok:true,id},documentMatch?200:201);
  }
  throw new HttpError(404,'Commander resource not found.');
 }
 if(path==='/api/workspace'&&method==='GET')return json(await workspaceData(e.DB));
 if(path==='/api/source-locations'&&(method==='POST'||method==='DELETE')){
  const d=await body(r),ip=normalizeIp(d.sourceIp);if(!ip)throw new HttpError(400,'A valid observed source IP is required.');
  if(!await e.DB.prepare('SELECT id FROM observations WHERE source_ip=? LIMIT 1').bind(ip).first())throw new HttpError(404,'This source is not present in the saved evidence.');
  if(method==='DELETE'){await e.DB.prepare('DELETE FROM source_locations WHERE source_ip=?').bind(ip).run();return json({ok:true});}
  let lat:number,lng:number,label:string,precision:string;
  if(d.mode==='country'){const country=countryLocation(field(d.country,120,true));if(!country)throw new HttpError(400,'Choose a supported country or enter coordinates.');lat=country.lat;lng=country.lng;label=country.name;precision='analyst-country';}
  else{if(!validCoordinates(d.lat,d.lng))throw new HttpError(400,'Enter valid source latitude and longitude.');lat=Number(d.lat);lng=Number(d.lng);label=field(d.label,120)||'Analyst-supplied location';precision='analyst';}
  await e.DB.prepare('INSERT INTO source_locations (source_ip,label,lat,lng,precision,updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(source_ip) DO UPDATE SET label=excluded.label,lat=excluded.lat,lng=excluded.lng,precision=excluded.precision,updated_at=excluded.updated_at').bind(ip,label,lat,lng,precision,new Date().toISOString()).run();return json({ok:true});
 }
 if(path==='/api/reports'&&method==='POST'){
  const d=await body(r),now=new Date().toISOString(),base=reportInstallation(d),siteId=base.id;
  const stmts:D1PreparedStatement[]=[];
  let incidentId:string,logKey:string|null=null;
   const title=field(d.title,180,true),summary=field(d.summary,6000,true),severity=field(d.severity,20,true),status=field(d.status,30,true),rawLog=field(d.rawLog,500000),fileName=field(d.fileName,200)||'pasted-log.txt';
   if(!severities.includes(severity)||!statuses.includes(status))throw new HttpError(400,'Choose a valid severity and status.');
   if(rawLog&&!d.reviewed)throw new HttpError(400,'Review the extracted details before saving.');
   if(new TextEncoder().encode(rawLog).length>500000)throw new HttpError(413,'Logs must be under 500 KB.');
   const logHash=rawLog?await digest(rawLog.replace(/\r\n/g,'\n').trim()):null;
   let parsed;try{parsed=ingestLog(rawLog);}catch(err){throw new HttpError(400,err instanceof Error?err.message:'Could not analyze this log.');}
   const events=parsed.events;const manualIp=normalizeIp(d.sourceIp);
   if(d.sourceIp&&!manualIp)throw new HttpError(400,'Enter a valid source IP or leave it blank.');
   const country=d.sourceCountry?countryLocation(field(d.sourceCountry,120)):undefined;if(d.sourceCountry&&!country)throw new HttpError(400,'Choose a recognized source country.');
   const hasSourceCoords=d.sourceLat!==undefined&&d.sourceLat!==''||d.sourceLng!==undefined&&d.sourceLng!=='';
   if((hasSourceCoords||country)&&!manualIp)throw new HttpError(400,'A source IP is required for a location override.');
   if(hasSourceCoords&&!validCoordinates(d.sourceLat,d.sourceLng))throw new HttpError(400,'Complete both source coordinates within valid ranges.');
   if(manualIp&&!events.length){const manual=ingestLog(JSON.stringify({source_ip:manualIp,destination_ip:d.targetIp,destination_port:d.targetPort})).events[0];if(manual)events.push({...manual,eventType:'manual_observation',lineNumber:0});}
   if(manualIp&&(hasSourceCoords||country))for(const event of events){if(event.sourceIp!==manualIp)continue;event.sourceLat=hasSourceCoords?Number(d.sourceLat):country!.lat;event.sourceLng=hasSourceCoords?Number(d.sourceLng):country!.lng;event.sourceLabel=field(d.sourceLabel,120)||country?.name||'Analyst-supplied location';event.precision=hasSourceCoords?'analyst':'analyst-country';}
   const metadataTarget=parseLog(rawLog).name;const namedTargets=[...new Set([...parsed.targets,...(metadataTarget?[metadataTarget]:[])])];
   for(const hint of namedTargets)if(!resolveInstallation(hint))throw new HttpError(400,`Log target “${hint}” is outside the approved U.S. military base list.`);
   if(d.targetMappings!==undefined){if(!d.targetMappings||typeof d.targetMappings!=='object'||Array.isArray(d.targetMappings))throw new HttpError(400,'Invalid target mappings.');for(const [hint,value]of Object.entries(d.targetMappings)){const target=resolveInstallation(hint),mapped=value==='primary'?base:installationById(value);if(!target||!mapped||target.id!==mapped.id)throw new HttpError(400,'Every log target must match its approved installation.');}}
   const mappedEvents=events.map(event=>({...event,id:crypto.randomUUID(),siteId:event.targetHint?resolveInstallation(event.targetHint)!.id:siteId,createdAt:now}));
   const directory=await fixedDirectory(e.DB),equivalentIds=directory.filter(row=>storedInstallation(row)?.id===siteId).map(row=>row.id);
   if(logHash&&await e.DB.prepare('SELECT id FROM incidents WHERE site_id IN (SELECT value FROM json_each(?)) AND log_hash=?').bind(JSON.stringify(equivalentIds),logHash).first())throw new HttpError(409,'This log is already saved for this installation. Re-uploading it would duplicate the evidence.');
   incidentId=crypto.randomUUID();
   if(rawLog){if(!e.BUCKET)throw new HttpError(503,'Log storage is unavailable.');logKey='logs/'+incidentId;await e.BUCKET.put(logKey,rawLog,{httpMetadata:{contentType:'text/plain; charset=utf-8'}});}
   const attackMetadata=buildAttackMetadata(mappedEvents,siteId,title,summary);
   stmts.push(e.DB.prepare('INSERT INTO incidents (id,site_id,title,summary,severity,status,log_key,file_name,created_at,updated_at,log_hash,attack_metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(incidentId,siteId,title,summary,severity,status,logKey,logKey?fileName:null,now,now,logHash,JSON.stringify(attackMetadata)));
   if(mappedEvents.length){const rows=mappedEvents.map(v=>({...v,incidentId}));const columns=['id','incident_id','site_id','source_ip','target_ip','target_port','protocol','username','event_type','outcome','occurred_at','source_label','source_lat','source_lng','precision','line_number','created_at'];const keys=['id','incidentId','siteId','sourceIp','targetIp','targetPort','protocol','username','eventType','outcome','occurredAt','sourceLabel','sourceLat','sourceLng','precision','lineNumber','createdAt'];stmts.push(e.DB.prepare(`INSERT INTO observations (${columns.join(',')}) SELECT ${keys.map(k=>`json_extract(value,'$.${k}')`).join(',')} FROM json_each(?)`).bind(JSON.stringify(rows)));}
   stmts.push(e.DB.prepare('UPDATE installations SET updated_at=? WHERE id=?').bind(now,siteId));
  try{await e.DB.batch(stmts);}catch(err){if(logKey)await e.BUCKET?.delete(logKey);if(err instanceof Error&&/UNIQUE constraint failed/.test(err.message))throw new HttpError(409,'This log is already saved for this installation.');throw err;}
  return json({siteId,incidentId},201);
 }
 if(path==='/api/sites'&&method==='POST')throw new HttpError(405,'The installation list is fixed. Installation creation is disabled.');
 const siteMatch=path.match(/^\/api\/sites\/([a-z0-9-]+)$/);
 if(siteMatch){
  const base=installationById(siteMatch[1]);if(!base)throw new HttpError(404,'Installation is not in the approved base list.');
  if(method!=='PATCH')throw new HttpError(405,'Approved installations cannot be created or deleted. Only contact updates are supported.');
  const data=await body(r);if(Object.keys(data).some(key=>!['contactName','contactEmail','contactPhone'].includes(key)))throw new HttpError(400,'Only contact information can be edited. Installation names, regions, and map locations are fixed.');
  const directory=await fixedDirectory(e.DB),prior=directory.find(row=>row.id===base.id)!,d=contactFields(data,prior);
  await e.DB.prepare('UPDATE installations SET contact_name=?,contact_email=?,contact_phone=?,updated_at=? WHERE id=?').bind(d.contactName,d.contactEmail,d.contactPhone,new Date().toISOString(),base.id).run();return json({ok:true});
 }
 const incidentMatch=path.match(/^\/api\/incidents\/([a-f0-9-]+)$/);
 if(incidentMatch&&method==='PATCH'){
  const record=await e.DB.prepare('SELECT site_id AS siteId FROM incidents WHERE id=?').bind(incidentMatch[1]).first<{siteId:string}>();if(!record)throw new HttpError(404,'Incident not found.');const directory=await fixedDirectory(e.DB),row=directory.find(row=>row.id===record.siteId);if(!row||!storedInstallation(row))throw new HttpError(400,'Reports outside the approved base list are retained as legacy records and cannot be updated.');
  const d=await body(r);if(Object.keys(d).some(key=>key!=='status'))throw new HttpError(400,'Only incident status can be updated. Targets must remain in the approved base list.');if(!statuses.includes(d.status))throw new HttpError(400,'Invalid incident status.');const result=await e.DB.prepare('UPDATE incidents SET status=?,updated_at=? WHERE id=?').bind(d.status,new Date().toISOString(),incidentMatch[1]).run();if(!result.meta.changes)throw new HttpError(404,'Incident not found.');return json({ok:true});
 }
 const logMatch=path.match(/^\/api\/logs\/([a-f0-9-]+)$/);
 if(logMatch&&method==='GET'){
  const i=await e.DB.prepare('SELECT log_key,file_name FROM incidents WHERE id=?').bind(logMatch[1]).first<{log_key:string;file_name:string}>();if(!i?.log_key)throw new HttpError(404,'No source log attached.');const file=await e.BUCKET?.get(i.log_key);if(!file)throw new HttpError(404,'Source log not found.');return new Response(file.body,{headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store, private','X-Content-Type-Options':'nosniff','Content-Disposition':`attachment; filename="${(i.file_name??'source-log.txt').replace(/[^a-zA-Z0-9._-]/g,'_')}"`}});
 }
 throw new HttpError(404,'Not found.');
}
export async function api(request:Request,env:Cloudflare.Env){try{return await handle(request,env);}catch(err){if(err instanceof HttpError)return json({error:err.message},err.status);console.error('Sentinel API operation failed',err instanceof Error?err.name:'UnknownError');return json({error:'Could not complete this request. Please try again.'},500);}}
