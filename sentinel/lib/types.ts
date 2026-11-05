import type {ReportAttackMetadata} from './attack-metadata';
import type {ExposureAssessment} from './exposure';
export type Severity = 'low'|'medium'|'high'|'critical';
export type IncidentStatus = 'reported'|'investigating'|'resolved';
export interface Installation {id:string;name:string;region:string;lat:number;lng:number;contactName:string;contactEmail:string;contactPhone:string;createdAt:string;updatedAt:string;}
export interface ReportLogBrief {siteId:string;analyzedEvents:number;sourceIps:string[];sourceLocations:string[];targetIps:string[];targetPorts:number[];protocols:string[];eventTypes:string[];outcomes:string[];firstSeen:string|null;lastSeen:string|null;}
export interface Incident {id:string;siteId:string;title:string;summary:string;severity:Severity;status:IncidentStatus;targetSiteIds?:string[];logBriefs?:ReportLogBrief[];attackMetadata?:ReportAttackMetadata;hasLog:boolean;fileName:string|null;createdAt:string;updatedAt:string;}
export interface Workspace {sites:Installation[];incidents:Incident[];updatedAt:string;analysis?:ThreatAnalysis;membership?:{installationId:string;installationName:string};exposure?:ExposureAssessment;}
export const severityRank:Record<string,number>={low:1,medium:2,high:3,critical:4};
export function activeFor(siteId:string,incidents:Incident[]){return incidents.filter(i=>(i.siteId===siteId||i.targetSiteIds?.includes(siteId))&&i.status!=='resolved');}
export function siteSeverity(siteId:string,incidents:Incident[]):Severity|'none'{return activeFor(siteId,incidents).sort((a,b)=>severityRank[b.severity]-severityRank[a.severity])[0]?.severity??'none';}
export function prioritizeInstallations(sites:Installation[],incidents:Incident[]):Installation[]{
 const priorities=new Map<string,{severity:number;count:number}>();
 for(const incident of incidents){
  if(incident.status==='resolved')continue;
  for(const id of new Set([incident.siteId,...(incident.targetSiteIds??[])])){
   const prior=priorities.get(id)??{severity:0,count:0};
   priorities.set(id,{severity:Math.max(prior.severity,severityRank[incident.severity]),count:prior.count+1});
  }
 }
 return sites.map((site,index)=>({site,index,...(priorities.get(site.id)??{severity:0,count:0})})).sort((a,b)=>b.severity-a.severity||b.count-a.count||a.index-b.index).map(item=>item.site);
}
export type LocationPrecision='logged'|'country'|'analyst'|'analyst-country'|'unknown';
export interface Observation {id:string;incidentId:string;siteId:string;sourceIp:string;targetIp:string|null;targetPort:number|null;protocol:string;username:string;eventType:string;outcome:string;occurredAt:string|null;sourceLabel:string;sourceLat:number|null;sourceLng:number|null;precision:LocationPrecision;lineNumber:number;createdAt:string;}
export interface SourceLocation {sourceIp:string;label:string;lat:number;lng:number;precision:LocationPrecision;updatedAt:string;}
export interface SourceSummary {ip:string;label:string;lat:number|null;lng:number|null;precision:LocationPrecision;scope:string;eventCount:number;targetIds:string[];reportCount:number;lastSeen:string|null;locationConflict:boolean;}
export interface ThreatFlow {id:string;sourceIp:string;sourceLabel:string;sourceLat:number|null;sourceLng:number|null;precision:LocationPrecision;targetSiteId:string;eventCount:number;reportCount:number;lastSeen:string|null;}
export interface PatternSignal {id:string;rule:string;title:string;severity:Severity;sourceIp:string;targetIds:string[];eventCount:number;reportCount:number;reason:string;window:string;firstSeen:string|null;lastSeen:string|null;evidence:Observation[];}
export interface ThreatAnalysis {version:string;totalEvents:number;analyzedEvents:number;truncated:boolean;sourceCount:number;mappedSourceCount:number;targetCount:number;sources:SourceSummary[];flows:ThreatFlow[];patterns:PatternSignal[];timestampedEvents:number;}
