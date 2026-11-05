/** Reported attack labels support correlation, not verification of exploitation. */
export interface AttackIndicators {cves:string[];signatures:string[];products:string[];synthetic:boolean;}
export interface ReportAttackMetadata {version:1;source:'log'|'report-text';targets:({siteId:string}&AttackIndicators)[];}
const LIMIT=20;
const key=(value:string)=>value.toLowerCase().replace(/[^a-z0-9]/g,'');
const cveKeys=new Set(['cve','cves','cveid','cveids','vulnerabilityid','vulnerabilitycve','vulnerabilitycves','vulnerabilitycveid','vulnerabilitycveids']);
const signatureKeys=new Set(['signature','signatures','signatureid','signatureids','detectionsignature','detectionsignatures','detectionsignatureid','detectionsignatureids','ruleid','rulename','threatsignature','alertsignature']);
const productKeys=new Set(['affectedproduct','affectedproducts','product','products','productname','productnames','vulnerabilityproduct','softwareproduct','serviceproduct']);
const empty=():AttackIndicators=>({cves:[],signatures:[],products:[],synthetic:false});
function values(value:unknown):string[]{
 if(Array.isArray(value))return value.filter((item):item is string=>typeof item==='string');
 if(typeof value==='string'&&value.trim().startsWith('[')){try{const parsed=JSON.parse(value);if(Array.isArray(parsed))return parsed.filter((item):item is string=>typeof item==='string');}catch{}}
 return typeof value==='string'||typeof value==='number'?[String(value)]:[];
}
const unique=(items:string[])=>[...new Set(items)].slice(0,LIMIT);
const clean=(value:string)=>value.replace(/[\r\n\t]+/g,' ').trim().slice(0,120);
export function reportedCves(value:string){return unique((value.slice(0,12000).match(/\bCVE-\d{4}-\d{4,10}\b/gi)??[]).map(item=>item.toUpperCase()));}
export function specificSignature(value:string){
 const signature=clean(value).toLowerCase();
 if(signature.length<6||/^(?:AUTH|NET|VOL|CORR)-\d+$/i.test(signature)||/^\d{1,5}$/.test(signature))return '';
 if(/[.:]/.test(signature)&&/^[\da-f:.]+$/i.test(signature))return '';
 if(/^(?:authentication|network[ _-]?event|network[ _-]?probe|manual[ _-]?observation|exploit[ _-]?signature|rce|sql[ _-]?injection|remote[ _-]?code[ _-]?execution|buffer[ _-]?overflow|success|failure|blocked|allowed|login|logon|malware|phishing|port[ _-]?scan|brute[ _-]?force)$/i.test(signature))return '';
 return signature;
}
/** Only explicit CVE/signature/product fields are collected; generic event text is not an attack identity. */
export function extractAttackIndicators(fields:Record<string,unknown>,defaults:Record<string,unknown>={}):AttackIndicators{
 const local=Object.fromEntries(Object.entries(fields).map(([name,value])=>[key(name),value]));
 const inherited=Object.fromEntries(Object.entries(defaults).map(([name,value])=>[key(name),value]));
 const collect=(keys:Set<string>)=>{const entries=Object.entries(local).filter(([name])=>keys.has(name));return (entries.length?entries:Object.entries(inherited).filter(([name])=>keys.has(name))).flatMap(([,value])=>values(value));};
 const truth=(value:unknown)=>value===true||value===1||typeof value==='string'&&/^(?:true|1|yes)$/i.test(value.trim());
 return {cves:unique(collect(cveKeys).flatMap(reportedCves)),signatures:unique(collect(signatureKeys).map(specificSignature).filter(Boolean)),products:unique(collect(productKeys).map(value=>clean(value).toLowerCase()).filter(Boolean)),synthetic:['synthetic','simulation','simulated','training'].some(name=>truth(local[name])||truth(inherited[name]))};
}
function sanitize(input:unknown):AttackIndicators{
 const object=input&&typeof input==='object'?input as Record<string,unknown>:{};
 return {cves:unique(values(object.cves).flatMap(reportedCves)),signatures:unique(values(object.signatures).map(specificSignature).filter(Boolean)),products:unique(values(object.products).map(value=>clean(value).toLowerCase()).filter(Boolean)),synthetic:object.synthetic===true};
}
/** Metadata remains grouped by the actual mapped event target. No event leaks labels to a different base. */
export function buildAttackMetadata(events:{siteId:string;attack?:AttackIndicators}[],primarySiteId:string,title:string,summary:string):ReportAttackMetadata{
 const groups=new Map<string,AttackIndicators>();
 for(const event of events){
  const current=groups.get(event.siteId)??empty(),attack=sanitize(event.attack);
  groups.set(event.siteId,{cves:unique([...current.cves,...attack.cves]),signatures:unique([...current.signatures,...attack.signatures]),products:unique([...current.products,...attack.products]),synthetic:current.synthetic||attack.synthetic});
 }
 let source:ReportAttackMetadata['source']='log';
 if(![...groups.values()].some(group=>group.cves.length||group.signatures.length)){
  const cves=reportedCves(title+'\n'+summary),synthetic=/\b(?:demo|synthetic|simulated|training)\b/i.test(title+' '+summary);
  const current=groups.get(primarySiteId)??empty();
  groups.set(primarySiteId,{...current,cves,synthetic:current.synthetic||synthetic});
  source='report-text';
 }
 return {version:1,source,targets:[...groups].map(([siteId,attack])=>({siteId,...attack}))};
}
/** Legacy fallback is explicitly report-text provenance; no recurring R2 reads or invented identifiers. */
export function readAttackMetadata(raw:unknown,title:string,summary:string,primarySiteId:string):ReportAttackMetadata{
 let value=raw;
 if(typeof value==='string'){try{value=value.length<200000?JSON.parse(value):null;}catch{value=null;}}
 if(value&&typeof value==='object'){
  const object=value as Record<string,unknown>;
  if(object.version===1&&(object.source==='log'||object.source==='report-text')&&Array.isArray(object.targets)){
   const groups=new Map<string,AttackIndicators>();
   for(const item of object.targets.slice(0,30)){
    if(!item||typeof item!=='object')continue;
    const row=item as Record<string,unknown>;
    if(typeof row.siteId!=='string'||!/^[a-z0-9-]{1,80}$/.test(row.siteId))continue;
    const prior=groups.get(row.siteId)??empty(),attack=sanitize(row);
    groups.set(row.siteId,{cves:unique([...prior.cves,...attack.cves]),signatures:unique([...prior.signatures,...attack.signatures]),products:unique([...prior.products,...attack.products]),synthetic:prior.synthetic||attack.synthetic});
   }
   if(groups.size)return {version:1,source:object.source,targets:[...groups].map(([siteId,attack])=>({siteId,...attack}))};
  }
 }
 return buildAttackMetadata([],primarySiteId,title,summary);
}
