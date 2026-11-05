import type {IncidentStatus,Severity,Workspace} from './types';
import {severityRank} from './types';
import {HOME_INSTALLATION_ID,HOME_MEMBERSHIP} from './home-base';
import {buildExposureAssessment,type ExposureAssessment} from './exposure';

export type CommanderDocumentKind='aar'|'coa';
export interface CommanderDocument {
 id:string;kind:CommanderDocumentKind;incidentId:string|null;title:string;body:string;
 status:'draft'|'reviewed';revision:number;createdAt:string;updatedAt:string;
}
export interface CommanderReport {
 id:string;title:string;summary:string;severity:Severity;status:IncidentStatus;
 installations:{id:string;name:string}[];createdAt:string;updatedAt:string;
}
export interface CommanderOverviewData {
 homeInstallation:{id:string;name:string};
 exposure:ExposureAssessment;
 updatedAt:string;
 counts:{active:number;elevated:number;awaitingReview:number;investigating:number;resolved:number;installations:number;totalInstallations:number;new24h:number};
 headline:string;summary:string;
 reports:CommanderReport[];
 severity:{key:Severity;label:string;count:number}[];
 trend:{date:string;label:string;count:number}[];
 installations:{id:string;name:string;active:number;elevated:number}[];
 activity:{label:string;count:number}[];
 documents:CommanderDocument[];
}
const activityLabels:Record<string,string>={
 'AUTH-01':'Repeated sign-in failures','AUTH-02':'Repeated sign-in failures',
 'AUTH-03':'A sign-in succeeded after repeated failures','NET-01':'Several network services were probed',
 'VOL-01':'A concentrated burst of logged activity','CORR-01':'Related activity across installations',
 'CORR-02':'Related activity across reports',
};
export const reportStatusLabel:Record<IncidentStatus,string>={reported:'Awaiting review',investigating:'Under investigation',resolved:'Resolved'};
export const priorityLabel:Record<Severity,string>={critical:'Critical',high:'High',medium:'Moderate',low:'Low'};

export function buildCommanderOverview(workspace:Workspace,documents:CommanderDocument[]=[],now=new Date()):CommanderOverviewData {
 const homeId=HOME_INSTALLATION_ID;
 const exposure=workspace.exposure??buildExposureAssessment(workspace,homeId,now);
 workspace={...workspace,sites:workspace.sites.filter(site=>site.id===homeId),incidents:workspace.incidents.filter(report=>report.siteId===homeId||report.targetSiteIds?.includes(homeId))};
 const localIds=new Set(workspace.incidents.map(report=>report.id));
 documents=documents.filter(document=>!document.incidentId||localIds.has(document.incidentId));
 const reports:CommanderReport[]=workspace.incidents.map(i=>({id:i.id,title:i.title,summary:i.summary,severity:i.severity,status:i.status,installations:[...new Set([i.siteId,...(i.targetSiteIds??[])])].flatMap(id=>{const site=workspace.sites.find(s=>s.id===id);return site?[{id:site.id,name:site.name}]:[];}),createdAt:i.createdAt,updatedAt:i.updatedAt})).sort((a,b)=>Number(a.status==='resolved')-Number(b.status==='resolved')||severityRank[b.severity]-severityRank[a.severity]||b.updatedAt.localeCompare(a.updatedAt));
 const active=reports.filter(r=>r.status!=='resolved'),activeIds=new Set(active.map(r=>r.id));
 const installations=workspace.sites.map(site=>{const linked=active.filter(r=>r.installations.some(s=>s.id===site.id));return {id:site.id,name:site.name,active:linked.length,elevated:linked.filter(r=>['critical','high'].includes(r.severity)).length};}).filter(s=>s.active>0).sort((a,b)=>b.elevated-a.elevated||b.active-a.active||a.name.localeCompare(b.name));
 const counts={active:active.length,elevated:active.filter(r=>['critical','high'].includes(r.severity)).length,awaitingReview:active.filter(r=>r.status==='reported').length,investigating:active.filter(r=>r.status==='investigating').length,resolved:reports.filter(r=>r.status==='resolved').length,installations:installations.length,totalInstallations:workspace.sites.length,new24h:reports.filter(r=>{const t=Date.parse(r.createdAt);return t<=now.getTime()&&t>now.getTime()-86400000;}).length};
 const severity=(['critical','high','medium','low'] as const).map(key=>({key,label:priorityLabel[key],count:active.filter(r=>r.severity===key).length}));
 const trend=Array.from({length:7},(_,index)=>{const start=new Date(now);start.setUTCHours(0,0,0,0);start.setUTCDate(start.getUTCDate()-6+index);const date=start.toISOString().slice(0,10);return {date,label:start.toLocaleDateString('en-US',{month:'short',day:'numeric',timeZone:'UTC'}),count:reports.filter(r=>r.createdAt.slice(0,10)===date).length};});
 const grouped=new Map<string,number>();
 for(const signal of workspace.analysis?.patterns??[]){if(!signal.evidence.some(e=>e.siteId===homeId&&activeIds.has(e.incidentId)))continue;const label=activityLabels[signal.rule]??'Activity needing analyst review';grouped.set(label,(grouped.get(label)??0)+1);}
 const activity=[...grouped].map(([label,count])=>({label,count})).sort((a,b)=>b.count-a.count);
 const headline=counts.elevated?'Priority reports need attention.':counts.active?'Reported activity is being assessed.':'No active reports in the workspace.';
 const summary=counts.active?`${counts.active} active ${counts.active===1?'report covers':'reports cover'} ${counts.installations} ${counts.installations===1?'installation':'installations'}. ${counts.elevated?`${counts.elevated} ${counts.elevated===1?'is':'are'} marked high or critical priority. `:''}${counts.awaitingReview} ${counts.awaitingReview===1?'is':'are'} awaiting review and ${counts.investigating} ${counts.investigating===1?'is':'are'} under investigation.`:'There are no unresolved reports to brief. This reflects submitted reports; it does not establish that systems or missions are unaffected.';
 return {homeInstallation:{id:HOME_MEMBERSHIP.installationId,name:HOME_MEMBERSHIP.installationName},exposure,updatedAt:workspace.updatedAt,counts,headline,summary,reports,severity,trend,installations,activity,documents};
}

export function commanderDraft(kind:CommanderDocumentKind,report?:CommanderReport){
 const title=`${kind==='aar'?'After-Action Report':'Course of Action'}${report?' — '+report.title:''}`.slice(0,180);
 const context=report?`${report.title}\nInstallation(s): ${report.installations.map(s=>s.name).join(', ')}\nReported priority: ${priorityLabel[report.severity]}\nCurrent status: ${reportStatusLabel[report.status]}\n\nReport summary:\n${report.summary}`:'Describe the situation and the installations involved.';
 const body=kind==='aar'?`SITUATION\n${context}\n\nRECORDED OUTCOME\n${report?.status==='resolved'?'The report is marked resolved. Restoration and mission impact still require confirmation.':'Review in progress. A final outcome has not been documented.'}\n\nACTIONS TAKEN\nNot documented. Add verified actions and their times.\n\nWHAT WORKED / WHAT NEEDS IMPROVEMENT\nNot documented. Capture the team’s findings.\n\nFOLLOW-UP\nRecord each action, responsible lead, and due date.\n\nREVIEW NOTE\nDraft assembled from submitted report details. Confirm the facts before marking reviewed.`:`SITUATION\n${context}\n\nOBJECTIVE\nConfirm the effect on the mission and protect essential services.\n\nOPTION 1 — VALIDATE AND MONITOR\nAsk the cyber team to verify the alert, determine mission impact, and provide an update.\nBenefit: Supports an informed decision.\nTrade-off: Additional verification takes time while the activity may continue.\n\nOPTION 2 — FOCUSED PROTECTION\nAsk the cyber team for a targeted response plan for affected services, coordinated with their mission owners.\nBenefit: Focuses effort on the reported concern.\nTrade-off: Selected services may be interrupted; confirm the impact before authorizing changes.\n\nOPTION 3 — BROADER PROTECTION\nRequest a wider protective plan if verified activity affects additional services or installations.\nBenefit: Addresses a larger confirmed problem.\nTrade-off: May require more resources and cause wider disruption.\n\nCOMMANDER’S DECISION\nNot recorded. Document the chosen approach, approval conditions, responsible lead, and next update time.\n\nPLANNING NOTE\nThese are planning options, not an approved response. Saving or reviewing this document does not execute any action.`;
 return {title,body,kind,incidentId:report?.id??null,status:'draft' as const};
}
