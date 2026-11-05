import type {Observation,ReportLogBrief,SourceLocation} from './types';

const SAMPLE_LIMIT=3;

function sample<T extends string|number>(values:T[],value:T|null){
 if(value===null||values.length>=SAMPLE_LIMIT)return;
 const item=typeof value==='string'?value.trim() as T:value;
 if(item!==''&&!values.includes(item))values.push(item);
}

/** Summarize the caller's canonical analysis window without exposing full events. */
export function reportLogBriefs(observations:Observation[],locations:SourceLocation[]=[]):Map<string,ReportLogBrief[]>{
 const overrides=new Map(locations.map(location=>[location.sourceIp,location.label.trim()]));
 const reports=new Map<string,Map<string,ReportLogBrief>>();
 for(const event of observations){
  let sites=reports.get(event.incidentId);
  if(!sites){sites=new Map();reports.set(event.incidentId,sites);}
  let brief=sites.get(event.siteId);
  if(!brief){
   brief={siteId:event.siteId,analyzedEvents:0,sourceIps:[],sourceLocations:[],targetIps:[],targetPorts:[],protocols:[],eventTypes:[],outcomes:[],firstSeen:null,lastSeen:null};
   sites.set(event.siteId,brief);
  }
  brief.analyzedEvents++;
  sample(brief.sourceIps,event.sourceIp);
  sample(brief.sourceLocations,overrides.get(event.sourceIp)||event.sourceLabel);
  sample(brief.targetIps,event.targetIp);
  sample(brief.targetPorts,event.targetPort);
  sample(brief.protocols,event.protocol);
  sample(brief.eventTypes,event.eventType);
  sample(brief.outcomes,event.outcome);
  if(event.occurredAt){
   if(brief.firstSeen===null||event.occurredAt<brief.firstSeen)brief.firstSeen=event.occurredAt;
   if(brief.lastSeen===null||event.occurredAt>brief.lastSeen)brief.lastSeen=event.occurredAt;
  }
 }
 return new Map([...reports].map(([incidentId,sites])=>[incidentId,[...sites.values()]]));
}
