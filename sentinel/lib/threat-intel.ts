import type {IntelEntry,IntelSourceId,IntelSourceState,ThreatIntelFeed} from './intel-types';
export const INTEL_REFRESH_MS=300_000;
export const INTEL_SOURCES=[
 {id:'cisa' as const,name:'CISA',description:'Known Exploited Vulnerabilities',homepage:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',feedUrl:'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',note:'Newest catalog addition, delivered through CISA’s official GitHub mirror. Added dates are catalog dates, not exploit start times.'},
 {id:'sans' as const,name:'SANS ISC',description:'Internet Storm Center diary',homepage:'https://isc.sans.edu/',feedUrl:'https://isc.sans.edu/rssfeed.xml',note:'Newest available diary entry. The title and short excerpt link to SANS research and analysis.'},
 {id:'nist' as const,name:'NIST NVD',description:'New vulnerability disclosures',homepage:'https://nvd.nist.gov/',feedUrl:'https://services.nvd.nist.gov/rest/json/cves/2.0',note:'Newest available CVE published in the preceding 24 hours. CVSS is shown only when the record provides it; publication does not confirm exploitation.'},
];
type Source=typeof INTEL_SOURCES[number];
export interface IntelPayload {items:IntelEntry[];totalAvailable:number|null;sourceUpdatedAt:string|null;}
interface CacheRow {source:string;payload:string|null;fetched_at:number|null;last_attempt_at:number;next_attempt_at:number;fetching_until:number;last_error:string|null;etag:string|null;last_modified:string|null;}
export type FeedFetch=(input:string,init?:RequestInit)=>Promise<Response>;
const asISO=(n:number|null)=>n===null?null:new Date(n).toISOString();
export function intelDate(v:unknown):string|null{if(typeof v!=='string'||!v.trim())return null;let s=v.trim();if(/^\d{4}-\d\d-\d\d$/.test(s))s+='T00:00:00Z';else if(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?$/.test(s))s+='Z';const n=Date.parse(s);return Number.isFinite(n)?new Date(n).toISOString():null;}
export function intelText(input:unknown,max=300):string{
 let s=typeof input==='string'?input.slice(0,30000):'';s=s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1');
 for(let i=0;i<3;i++)s=s.replace(/&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi,(_,entity:string)=>{const key=entity.toLowerCase();if(key[0]==='#'){const code=key[1]==='x'?parseInt(key.slice(2),16):parseInt(key.slice(1),10);return code>0&&code<=0x10ffff&&!(code>=0xd800&&code<=0xdfff)?String.fromCodePoint(code):'';}return ({amp:'&',lt:'<',gt:'>',quot:'"',apos:"'",nbsp:' '} as Record<string,string>)[key]??'';});
 s=s.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,' ').replace(/<[^>]*>/g,' ').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g,'').replace(/\s+/g,' ').trim();
 return s.length>max?s.slice(0,max-1).trimEnd()+'…':s;
}
const validCve=(v:unknown)=>typeof v==='string'&&/^CVE-\d{4}-\d{4,19}$/i.test(v)?v.toUpperCase():null;
function emptyEntry(source:IntelSourceId,id:string):IntelEntry{return {id,source,title:'',summary:'',url:'',cve:null,publishedAt:null,updatedAt:null,dateLabel:'Published',kind:'research',severity:'unrated',score:null,scoreSource:null,action:null,dueDate:null,ransomwareKnown:false,tags:[]};}
function latest(items:IntelEntry[],limit:number){return [...new Map(items.map(i=>[i.id,i])).values()].sort((a,b)=>(b.publishedAt??'').localeCompare(a.publishedAt??'')||a.id.localeCompare(b.id)).slice(0,limit);}
export function parseCisaFeed(data:any):IntelPayload{
 if(!data||!Array.isArray(data.vulnerabilities))throw Error('CISA returned an unexpected catalog format.');
 const items:IntelEntry[]=[];for(const v of data.vulnerabilities){const cve=validCve(v?.cveID);if(!cve)continue;const title=intelText(v.vulnerabilityName,220);if(!title)continue;items.push({...emptyEntry('cisa','cisa:'+cve),title,summary:intelText(v.shortDescription,300),url:INTEL_SOURCES[0].homepage,cve,publishedAt:intelDate(v.dateAdded),dateLabel:'Added to KEV',kind:'known-exploited',action:intelText(v.requiredAction,600)||null,dueDate:intelDate(v.dueDate),ransomwareKnown:v.knownRansomwareCampaignUse==='Known',tags:[intelText(v.vendorProject,70),intelText(v.product,90)].filter(Boolean)});}
 if(data.vulnerabilities.length&&!items.length)throw Error('CISA catalog contained no valid entries.');
 return {items:latest(items,40),totalAvailable:items.length,sourceUpdatedAt:intelDate(data.dateReleased)};
}
function xmlField(block:string,name:string){return new RegExp('<'+name+'(?:\\s[^>]*)?>([\\s\\S]*?)<\\/'+name+'\\s*>','i').exec(block)?.[1]??'';}
function sansUrl(v:string){try{const url=new URL(intelText(v,1500));if(url.protocol!=='https:'||url.hostname!=='isc.sans.edu')return null;return url.href;}catch{return null;}}
export function parseSansFeed(xml:string):IntelPayload{
 if(/<!DOCTYPE|<!ENTITY/i.test(xml)||!/<rss\b/i.test(xml)||!/<channel\b/i.test(xml))throw Error('SANS returned an unexpected RSS format.');
 const items:IntelEntry[]=[];for(const match of xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item\s*>/gi)){const block=match[1],url=sansUrl(xmlField(block,'link')),title=intelText(xmlField(block,'title'),220);if(!url||!title)continue;items.push({...emptyEntry('sans','sans:'+url),title,summary:intelText(xmlField(block,'description'),280),url,publishedAt:intelDate(intelText(xmlField(block,'pubDate'),120)),tags:['Handler’s diary']});if(items.length>=100)break;}
 if(/<item\b/i.test(xml)&&!items.length)throw Error('SANS RSS contained no valid publisher links.');
 return {items:latest(items,20),totalAvailable:items.length,sourceUpdatedAt:intelDate(intelText(xmlField(xml.split('<item')[0],'lastBuildDate'),120))};
}
export function parseNvdFeed(data:any):IntelPayload{
 if(!data||!Array.isArray(data.vulnerabilities)||!Number.isFinite(data.totalResults))throw Error('NIST returned an unexpected vulnerability format.');
 const items:IntelEntry[]=[];for(const row of data.vulnerabilities){const v=row?.cve,cve=validCve(v?.id);if(!cve||v.vulnStatus==='Rejected')continue;const descriptions=Array.isArray(v.descriptions)?v.descriptions:[],description=descriptions.find((d:any)=>d.lang==='en')?.value??'';
  let score:number|null=null,scoreSource:string|null=null;
  for(const key of ['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2']){const metrics=Array.isArray(v.metrics?.[key])?v.metrics[key]:[];const metric=[...metrics].sort((a:any,b:any)=>(b.type==='Primary'?1:0)-(a.type==='Primary'?1:0)).find((m:any)=>typeof m.cvssData?.baseScore==='number'&&m.cvssData.baseScore>=0&&m.cvssData.baseScore<=10);if(metric){score=metric.cvssData.baseScore;scoreSource=intelText(metric.source,160)||null;break;}}
  const severity=score===null?'unrated':score>=9?'critical':score>=7?'high':score>=4?'medium':'low';
  items.push({...emptyEntry('nist','nist:'+cve),title:cve,summary:intelText(description,420)||'No English description is currently available in the publisher record.',url:'https://nvd.nist.gov/vuln/detail/'+cve,cve,publishedAt:intelDate(v.published),updatedAt:intelDate(v.lastModified),dateLabel:'CVE published',kind:'vulnerability',severity,score,scoreSource,tags:[intelText(v.vulnStatus,60)||'Published record']});
 }
 if(data.vulnerabilities.length&&!items.length&&data.vulnerabilities.some((v:any)=>v?.cve?.vulnStatus!=='Rejected'))throw Error('NIST returned no valid CVE records.');
 return {items:latest(items,60),totalAvailable:data.totalResults,sourceUpdatedAt:intelDate(data.timestamp)};
}
async function boundedText(response:Response,max=12_000_000){const reader=response.body?.getReader();if(!reader)return '';const chunks:Uint8Array[]=[];let length=0;try{while(true){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>max){await reader.cancel();throw Error('Publisher response exceeded the feed size limit.');}chunks.push(value);}}finally{reader.releaseLock();}const out=new Uint8Array(length);let start=0;for(const c of chunks){out.set(c,start);start+=c.length;}return new TextDecoder().decode(out);}
async function publisherResponse(url:string,cache:CacheRow,fetcher:FeedFetch,conditional=true,timeoutMs=18000){const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),timeoutMs);try{
 const headers:Record<string,string>={'Accept':'application/json, application/rss+xml, application/xml, text/xml;q=0.9, */*;q=0.5','User-Agent':'Sentinel-Public-Intel/1.0'};if(conditional&&cache.etag)headers['If-None-Match']=cache.etag;if(conditional&&cache.last_modified)headers['If-Modified-Since']=cache.last_modified;
 const r=await fetcher(url,{headers,signal:controller.signal,redirect:'manual'});if(r.status===304)return {notModified:true as const,text:'',etag:cache.etag,modified:cache.last_modified};if(!r.ok)throw Error(r.status===429?'Publisher rate limit reached. Retrying on the next five-minute check.':`Publisher returned HTTP ${r.status}. Retrying on the next five-minute check.`);
 const text=await boundedText(r);return {notModified:false as const,text,etag:r.headers.get('etag'),modified:r.headers.get('last-modified')};
 }catch(err){if(controller.signal.aborted)throw Error('Publisher request timed out. Retrying on the next five-minute check.');throw err;}finally{clearTimeout(timeout);}}
async function fetchSource(source:Source,cache:CacheRow,fetcher:FeedFetch,now:number):Promise<{payload:IntelPayload|null;etag:string|null;modified:string|null;notModified:boolean}>{
 if(source.id==='nist'){
  const url=new URL(source.feedUrl);url.searchParams.set('resultsPerPage','2000');url.searchParams.set('pubStartDate',new Date(now-86400000).toISOString());url.searchParams.set('pubEndDate',new Date(now).toISOString());url.searchParams.set('noRejected','');
  let r=await publisherResponse(url.href,cache,fetcher,false,40000),data:any;try{data=JSON.parse(r.text);}catch{throw Error('NIST did not return valid JSON.');}
  if(Number.isFinite(data.totalResults)&&data.totalResults>2000){await new Promise(resolve=>setTimeout(resolve,6500));url.searchParams.set('resultsPerPage','60');url.searchParams.set('startIndex',String(data.totalResults-60));r=await publisherResponse(url.href,cache,fetcher,false,40000);try{data=JSON.parse(r.text);}catch{throw Error('NIST did not return valid JSON.');}}
  return {payload:parseNvdFeed(data),etag:null,modified:null,notModified:false};
 }
 const r=await publisherResponse(source.feedUrl,cache,fetcher);if(r.notModified)return {payload:null,etag:r.etag,modified:r.modified,notModified:true};
 let payload:IntelPayload;if(source.id==='cisa'){let data:any;try{data=JSON.parse(r.text);}catch{throw Error('CISA did not return valid JSON.');}payload=parseCisaFeed(data);}else payload=parseSansFeed(r.text);
 return {payload,etag:r.etag,modified:r.modified,notModified:false};
}
function payloadOf(row:CacheRow):IntelPayload|null{if(!row.payload)return null;try{const p=JSON.parse(row.payload);return Array.isArray(p.items)?p:null;}catch{return null;}}
export async function getThreatIntel(db:D1Database,fetcher:FeedFetch=(url,init)=>fetch(url,init),now=Date.now()):Promise<ThreatIntelFeed>{
 const results=await Promise.all(INTEL_SOURCES.map(async source=>{
  await db.prepare('INSERT OR IGNORE INTO threat_feed_cache (source,last_attempt_at,next_attempt_at,fetching_until) VALUES (?,0,0,0)').bind(source.id).run();
  let row=(await db.prepare('SELECT * FROM threat_feed_cache WHERE source=?').bind(source.id).first<CacheRow>())!;
  if(row.next_attempt_at<=now&&row.fetching_until<=now){const lease=now+90000;const claim=await db.prepare('UPDATE threat_feed_cache SET fetching_until=?,last_attempt_at=? WHERE source=? AND fetching_until<=? AND next_attempt_at<=? RETURNING source').bind(lease,now,source.id,now,now).first();
   if(claim){try{const result=await fetchSource(source,row,fetcher,now);const prior=payloadOf(row);if(result.notModified&&!prior)throw Error('Publisher returned an unchanged feed without a previous copy.');const payload=result.payload??prior!;
     await db.prepare('UPDATE threat_feed_cache SET payload=?,fetched_at=?,last_attempt_at=?,next_attempt_at=?,fetching_until=0,last_error=NULL,etag=?,last_modified=? WHERE source=? AND fetching_until=?').bind(JSON.stringify(payload),now,now,now+INTEL_REFRESH_MS,result.etag,result.modified,source.id,lease).run();
    }catch(err){const message=err instanceof Error?intelText(err.message,220):'Publisher is temporarily unavailable.';await db.prepare('UPDATE threat_feed_cache SET last_attempt_at=?,next_attempt_at=?,fetching_until=0,last_error=? WHERE source=? AND fetching_until=?').bind(now,now+INTEL_REFRESH_MS,message,source.id,lease).run();}
   }
   row=(await db.prepare('SELECT * FROM threat_feed_cache WHERE source=?').bind(source.id).first<CacheRow>())!;
  }
  const p=payloadOf(row),items=latest(p?.items??[],1),checking=row.fetching_until>now,status:IntelSourceState['status']=checking?'checking':row.last_error?(p?'stale':'unavailable'):p?(row.fetched_at!==null&&now-row.fetched_at>INTEL_REFRESH_MS+15000?'stale':'current'):'unavailable';
  const state:IntelSourceState={...source,status,checkedAt:asISO(row.fetched_at),attemptedAt:row.last_attempt_at?asISO(row.last_attempt_at):null,nextCheckAt:new Date(checking?now+15000:Math.max(now+1000,row.next_attempt_at)).toISOString(),latestEntryAt:p?.items.reduce<string|null>((d,i)=>i.publishedAt&&(!d||i.publishedAt>d)?i.publishedAt:d,null)??null,sourceUpdatedAt:p?.sourceUpdatedAt??null,count:items.length,totalAvailable:p?.totalAvailable??null,error:row.last_error,note:source.note};
  return {items,state};
 }));
 return {items:latest(results.flatMap(r=>r.items),INTEL_SOURCES.length),sources:results.map(r=>r.state),servedAt:new Date(now).toISOString(),nextRefreshAt:new Date(Math.min(...results.map(r=>Date.parse(r.state.nextCheckAt)))).toISOString(),refreshIntervalSeconds:INTEL_REFRESH_MS/1000};
}
