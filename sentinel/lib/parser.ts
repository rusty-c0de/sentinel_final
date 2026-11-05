export interface ParsedLog {name?:string;region?:string;lat?:string;lng?:string;contactName?:string;contactEmail?:string;contactPhone?:string;title?:string;summary?:string;severity?:string;status?:string;}
const aliases:Record<string,keyof ParsedLog>={installation:'name',installationname:'name',site:'name',sitename:'name',location:'name',targetinstallation:'name',targetsite:'name',name:'name',region:'region',latitude:'lat',lat:'lat',longitude:'lng',lon:'lng',long:'lng',lng:'lng',contact:'contactName',contactname:'contactName',poc:'contactName',email:'contactEmail',contactemail:'contactEmail',phone:'contactPhone',contactphone:'contactPhone',title:'title',incident:'title',incidenttype:'title',type:'title',summary:'summary',description:'summary',message:'summary',severity:'severity',level:'severity',status:'status'};
export function parseLog(raw:string):ParsedLog{
 const values:ParsedLog={};
 function assign(key:string,value:unknown){const k=aliases[key.toLowerCase().replace(/[^a-z]/g,'')];if(k&&(typeof value==='string'||typeof value==='number'))values[k]=String(value).trim();}
 try{const parsed=JSON.parse(raw);function walk(value:unknown,context=''){if(!value||Array.isArray(value)||typeof value!=='object')return;for(const[k,v]of Object.entries(value)){const c=k.toLowerCase();if(['source','src','events','records','logs'].includes(c))continue;if(v&&typeof v==='object')walk(v,c);else if(['contact','poc'].includes(context))assign(c==='name'?'contactName':c,v);else if(['incident','report'].includes(context)&&c==='name')assign('title',v);else assign(k,v);}}walk(parsed);}catch{}
 for(const line of raw.split(/\r?\n/)){const match=line.match(/^\s*([A-Za-z_ ]{2,24})\s*[:=]\s*(.+?)\s*$/);if(match)assign(match[1],match[2]);}
 const coords=raw.match(/(?:coordinates|coords)\s*[:=]\s*\(?\s*(-?\d+(?:\.\d+)?)\s*[,;]\s*(-?\d+(?:\.\d+)?)\s*\)?/i);
 if(coords){values.lat??=coords[1];values.lng??=coords[2];}
 for(const[k,max]of [['name',120],['region',120],['contactName',120],['contactEmail',200],['contactPhone',80],['title',180],['summary',6000]] as const)if(values[k])values[k]=values[k]!.slice(0,max);
 if(values.lat&&(!Number.isFinite(Number(values.lat))||Math.abs(Number(values.lat))>90))delete values.lat;
 if(values.lng&&(!Number.isFinite(Number(values.lng))||Math.abs(Number(values.lng))>180))delete values.lng;
 if(values.severity){const v=values.severity.toLowerCase();values.severity=({warning:'medium',warn:'medium',error:'high',fatal:'critical',info:'low'} as Record<string,string>)[v]??v;if(!['low','medium','high','critical'].includes(values.severity))delete values.severity;}
 if(values.status){values.status=values.status.toLowerCase();if(!['reported','investigating','resolved'].includes(values.status))delete values.status;}
 return values;
}
export const legacySampleLog=`Installation: Naval Station Norfolk
Region: Virginia, United States
Latitude: 36.946
Longitude: -76.302
Contact: Demo Duty Officer
Email: duty@example.invalid
Title: Simulated authentication anomaly
Severity: high
Status: reported
Summary: DEMO ONLY — repeated sign-in failures detected on a test network. Awaiting review.`;

export const sampleLog=JSON.stringify({installation:{name:'Naval Station Norfolk',region:'Virginia, United States',latitude:36.946,longitude:-76.302},contact:{name:'Demo Duty Officer',email:'duty@example.invalid'},title:'DEMO — repeated authentication failures',severity:'high',status:'reported',summary:'Synthetic training evidence only. Repeated failed logins and a later success from one observed source.',events:Array.from({length:7},(_,i)=>({timestamp:`2026-11-04T12:00:${String(i*6).padStart(2,'0')}Z`,source_ip:'203.0.113.21',source_country:'Netherlands',destination_ip:'10.14.0.10',destination_port:443,target_installation:'Naval Station Norfolk',event_type:'authentication',outcome:i===6?'success':'failure',username:'demo-user'}))},null,2);
