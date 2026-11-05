import type {Incident,IncidentStatus,Observation,ReportLogBrief,Severity,Workspace} from './types';
import {severityRank} from './types';
import {ipScope,normalizeIp} from './geo';
import {readAttackMetadata,specificSignature,type ReportAttackMetadata} from './attack-metadata';

export type ExposureLevel='high'|'partial'|'none'|'unavailable';
export type ExposureConfidence='limited'|'moderate';
export interface SimilarityBreakdown {
 key:'alerts'|'behaviors'|'services'|'sources'|'outcomes';label:string;weight:number;
 percent:number|null;points:number;matched:number;total:number;
}
export interface AttackSimilarity {
 percent:number|null;coverage:number;localReportId:string|null;localReportStatus:IncidentStatus|null;
 synthetic:boolean;basis:string;breakdown:SimilarityBreakdown[];
}
export interface ExposureComparison {
 id:string;reportId:string;title:string;installationId:string;installationName:string;severity:Severity;
 level:ExposureLevel;confidence:ExposureConfidence;reasons:string[];matchedAlerts:string[];matchedBehaviors:string[];
 localReportIds:string[];synthetic:boolean;updatedAt:string;similarity:AttackSimilarity;
}
export interface ExposureAssessment {
 homeSiteId:string;homeName:string;summary:string;level:ExposureLevel;confidence:ExposureConfidence;
 localActiveReports:number;comparisons:ExposureComparison[];limitations:string[];updatedAt:string;
 similarity:(AttackSimilarity&{comparisonId:string;reportId:string;installationName:string})|null;
}
const RECENT_MS=30*24*60*60*1000;
const MAX_LOCAL_REPORTS=100,MAX_REMOTE_REPORTS=250,MAX_TARGET_COMPARISONS=250,MAX_OBSERVATIONS=5000;
const order:Record<ExposureLevel,number>={high:3,partial:2,none:1,unavailable:0};
const intersect=<T,>(a:T[],b:T[])=>{const right=new Set(b);return [...new Set(a)].filter(value=>right.has(value));};
const unique=(values:string[])=>[...new Set(values)].sort();
const targets=(report:Incident)=>[...new Set([report.siteId,...(report.targetSiteIds??[])])];
const briefingTitle=(title:string)=>title.replace(/\[?[\da-f:.]+\]?/gi,value=>{const token=value.replace(/\.+$/,'');const prefix=token.startsWith(':')&&!normalizeIp(token)&&normalizeIp(token.slice(1))?':':'';return normalizeIp(token.slice(prefix.length))?prefix+'[network indicator]'+value.slice(token.length):value;}).slice(0,180);
const withoutCves=(value:string)=>value.replace(/\bCVE-\d{4}-\d{4,10}\b/gi,'').replace(/^[\s:;,|_-]+|[\s:;,|_-]+$/g,'');
function eventLabel(value:string){const label=withoutCves(value).trim().toLowerCase().replace(/[\s-]+/g,'_');return label&&!['unknown','none','n/a','not_provided','unspecified','network_event','manual_observation'].includes(label)?label:'';}
function detectionLabel(value:string){return specificSignature(withoutCves(value));}
const validPort=(port:number|null)=>port!==null&&Number.isInteger(port)&&port>0&&port<=65535;
function protocolLabel(value:string){const label=value.trim().toLowerCase();return /^[a-z][a-z0-9./-]{0,19}$/.test(label)&&!['unknown','none','unspecified'].includes(label)?label:'';}
function sourceLabel(value:string,synthetic:boolean){const ip=normalizeIp(value);if(!ip)return '';const documentation=/^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2001:db8:)/i.test(ip);return ipScope(ip)==='public'||synthetic&&documentation?ip:'';}
const fresh=(stamp:string|null|undefined,now:number)=>{const time=Date.parse(stamp??'');return Number.isFinite(time)&&time<=now&&now-time<=RECENT_MS;};
type Profile=Record<SimilarityBreakdown['key'],string[]>;
type Evidence={report:Incident;brief?:ReportLogBrief;recent:boolean;timed:boolean;complete:boolean;synthetic:boolean;profile:Profile};
type ScopedRows={rows:Observation[];provided:boolean};

/** Count only distinct, timestamped observations from one report, base and source. */
function behaviorLabels(rows:Observation[]):string[]{
 const result=new Set<string>(),bySource=new Map<string,Observation[]>();
 for(const row of rows){const source=normalizeIp(row.sourceIp);if(!source)continue;const group=bySource.get(source)??[];group.push(row);bySource.set(source,group);}
 const enoughInWindow=(group:Observation[],ms:number,threshold:number,ports=false)=>{
  const sorted=[...group].sort((a,b)=>a.occurredAt!.localeCompare(b.occurredAt!));let start=0;const counts=new Map<number,number>();
  for(let end=0;end<sorted.length;end++){
   if(ports){const port=sorted[end].targetPort!;counts.set(port,(counts.get(port)??0)+1);}
   while(Date.parse(sorted[end].occurredAt!)-Date.parse(sorted[start].occurredAt!)>ms){if(ports){const port=sorted[start].targetPort!,count=counts.get(port)!-1;if(count)counts.set(port,count);else counts.delete(port);}start++;}
   if((ports?counts.size:end-start+1)>=threshold)return true;
  }
  return false;
 };
 for(const group of bySource.values()){
  if(enoughInWindow(group.filter(row=>eventLabel(row.eventType)==='authentication'&&row.outcome.toLowerCase()==='failure'),600000,5))result.add('AUTH-01');
  if(enoughInWindow(group.filter(row=>validPort(row.targetPort)),600000,5,true))result.add('NET-01');
  if(enoughInWindow(group,60000,20))result.add('VOL-01');
 }
 return [...result].sort();
}
function scopedObservations(input:Observation[],reports:Incident[],now:number){
 const allowed=new Map(reports.map(report=>[report.id,new Set(targets(report))])),groups=new Map<string,ScopedRows>(),seenIds=new Set<string>(),seenEvents=new Set<string>();
 for(const row of input.slice(0,MAX_OBSERVATIONS)){
  if(!allowed.get(row.incidentId)?.has(row.siteId))continue;
  const key=row.incidentId+'|'+row.siteId,group=groups.get(key)??{rows:[],provided:true};groups.set(key,group);
  if(!fresh(row.occurredAt,now))continue;
  const idKey=key+'|'+row.id,eventKey=JSON.stringify([key,row.sourceIp,row.targetIp,row.targetPort,row.protocol,row.username,row.eventType,row.outcome,row.occurredAt]);
  if(seenIds.has(idKey)||seenEvents.has(eventKey))continue;seenIds.add(idKey);seenEvents.add(eventKey);group.rows.push(row);
 }
 return groups;
}
function evidence(report:Incident,siteId:string,now:number,groups:Map<string,ScopedRows>,metadata=readAttackMetadata(report.attackMetadata,report.title,report.summary,report.siteId)):Evidence{
 const attack=metadata.targets.find(target=>target.siteId===siteId),synthetic=attack?.synthetic===true||/\b(?:demo|synthetic|simulated|training)\b/i.test(report.title+' '+report.summary);
 const brief=report.logBriefs?.find(value=>value.siteId===siteId),scoped=groups.get(report.id+'|'+siteId),rows=scoped?.rows??[];
 // Sampled raw rows take precedence over report-wide brief arrays. Never reuse global patterns.
 const types=scoped?rows.map(row=>row.eventType):brief?.eventTypes??[];
 const ports=scoped?rows.map(row=>row.targetPort):brief?.targetPorts??[];
 const protocols=scoped?rows.map(row=>row.protocol):brief?.protocols??[];
 const sources=scoped?rows.map(row=>row.sourceIp):brief?.sourceIps??[];
 const outcomes=scoped?rows.map(row=>row.outcome):brief?.outcomes??[];
 const profile:Profile={
  alerts:unique([...types.map(eventLabel).filter(Boolean).map(value=>'event:'+value),...(attack?.signatures??[]).map(detectionLabel).filter(Boolean).map(value=>'detection:'+value)]),
  behaviors:behaviorLabels(rows),
  services:unique([...ports.filter(validPort).map(value=>'port:'+value),...protocols.map(protocolLabel).filter(Boolean).map(value=>'protocol:'+value)]),
  sources:unique(sources.map(value=>sourceLabel(value,synthetic)).filter(Boolean)),
  outcomes:unique(outcomes.map(value=>value.trim().toLowerCase()).filter(value=>['failure','success','blocked','allowed'].includes(value))),
 };
 const stamp=brief?.lastSeen??report.updatedAt,timed=!!brief?.lastSeen&&fresh(brief.lastSeen,now);
 return {report,brief,synthetic,profile,recent:fresh(stamp,now)&&(!scoped||rows.length>0),timed,complete:timed&&rows.length>0&&rows.length>=(brief?.analyzedEvents??rows.length)};
}
const dimensions=[{key:'alerts',label:'Alert types and detection labels',weight:40},{key:'behaviors',label:'Observed behavior patterns',weight:25},{key:'services',label:'Destination ports and protocols',weight:20},{key:'sources',label:'Source indicators',weight:10},{key:'outcomes',label:'Observed alert outcomes',weight:5}] as const;
const round=(value:number,places=0)=>Math.round(value*10**places)/10**places;
function similarityBreakdown(local?:Evidence,remote?:Evidence):SimilarityBreakdown[]{
 return dimensions.map(dimension=>{const left=local?.profile[dimension.key]??[],right=remote?.profile[dimension.key]??[],available=left.length>0&&right.length>0,total=new Set([...left,...right]).size,matched=intersect(left,right).length,ratio=available?matched/total:null;
  return {...dimension,percent:ratio===null?null:round(ratio*100,1),points:ratio===null?0:round(dimension.weight*ratio,2),matched,total};
 });
}
function individualSimilarity(local:Evidence,remote:Evidence):AttackSimilarity{
 const breakdown=similarityBreakdown(local,remote),coverage=breakdown.reduce((sum,row)=>sum+(row.percent===null?0:row.weight),0);
 const identifiable=breakdown.some(row=>(row.key==='alerts'||row.key==='behaviors')&&row.percent!==null);
 const percent=identifiable?Math.min(coverage,round(breakdown.reduce((sum,row)=>sum+(row.percent===null?0:row.weight*row.matched/row.total),0))):null;
 let basis=identifiable?'Best individual current local-alert report match. Missing categories earn no points; this compares observed alert evidence and is not an attack probability.':'A meaningful alert or qualifying behavior category must be present on both sides before an alert similarity percentage can be calculated.';
 if(!local.timed||!remote.timed)basis+=' Report update time substitutes for missing observed-event time.';
 if(!local.complete||!remote.complete)basis+=' Sampled event coverage is incomplete; behavior rules use only available fresh observations.';
 if(remote.synthetic)basis+=' This compares exercise alerts only.';
 return {percent,coverage,localReportId:local.report.id,localReportStatus:local.report.status,synthetic:remote.synthetic,basis,breakdown};
}
type SimilarityCandidate={result:AttackSimilarity;evidence:Evidence};
function candidateOrder(a:SimilarityCandidate,b:SimilarityCandidate){return (b.result.percent??-1)-(a.result.percent??-1)||b.result.coverage-a.result.coverage||b.evidence.report.updatedAt.localeCompare(a.evidence.report.updatedAt)||a.evidence.report.id.localeCompare(b.evidence.report.id);}
function attackSimilarity(locals:Evidence[],remote:Evidence):{result:AttackSimilarity;local?:Evidence}{
 const unavailable=(basis:string)=>({result:{percent:null,coverage:0,localReportId:null,localReportStatus:null,synthetic:remote.synthetic,basis,breakdown:similarityBreakdown()} as AttackSimilarity});
 if(!remote.recent)return unavailable('The other installation’s alert evidence is stale, invalid, or future-dated. Recent current alerts are required on both sides.');
 if(!locals.length)return unavailable('No current unresolved home-installation report is available. Add independent current local and external alerts to compare.');
 const independent=locals.filter(local=>local.report.id!==remote.report.id);
 if(!independent.length)return unavailable('A report cannot be compared with itself. An independent current home-installation report is required.');
 const sameContext=independent.filter(local=>local.synthetic===remote.synthetic);
 if(!sameContext.length)return unavailable('Exercise and operational alerts are kept separate and cannot be mixed for a percentage.');
 const recent=sameContext.filter(local=>local.recent);
 if(!recent.length)return unavailable('Current local alert evidence is stale, invalid, or future-dated. Both sides require evidence within the last 30 days.');
 let best:SimilarityCandidate|null=null;
 for(const local of recent){const candidate={result:individualSimilarity(local,remote),evidence:local};if(!best||candidateOrder(candidate,best)<0)best=candidate;}
 return {result:best!.result,local:best!.evidence};
}
/**
 * A fixed-weight comparison of current unresolved alerts in the shared globe dataset.
 * CVEs, products, country, severity, and raw event volume never earn similarity points.
 * Pattern thresholds identify observed behavior, not attacker identity or future risk.
 */
export function buildExposureAssessment(workspace:Workspace,homeSiteId:string,now=new Date(),observations:Observation[]=[]):ExposureAssessment{
 const current=now.getTime(),homeName=workspace.sites.find(site=>site.id===homeSiteId)?.name??'Home installation';
 const byRecent=(a:Incident,b:Incident)=>b.updatedAt.localeCompare(a.updatedAt)||a.id.localeCompare(b.id);
 const activeReports=workspace.incidents.filter(report=>report.status!=='resolved');
 const homeReports=activeReports.filter(report=>targets(report).includes(homeSiteId)).sort(byRecent),siteMap=new Map(workspace.sites.map(site=>[site.id,site]));
 const remoteReports=activeReports.filter(report=>targets(report).some(id=>id!==homeSiteId&&siteMap.has(id))).sort(byRecent);
 const selected=[...new Map([...homeReports.slice(0,MAX_LOCAL_REPORTS),...remoteReports.slice(0,MAX_REMOTE_REPORTS)].map(report=>[report.id,report])).values()];
 const groups=scopedObservations(observations,selected,current),locals=homeReports.slice(0,MAX_LOCAL_REPORTS).map(report=>evidence(report,homeSiteId,current,groups));
 let evaluatedTargets=0,moreTargets=false;const comparisons:ExposureComparison[]=[];
 remoteLoop:for(const report of remoteReports.slice(0,MAX_REMOTE_REPORTS)){
  const metadata=readAttackMetadata(report.attackMetadata,report.title,report.summary,report.siteId);
  for(const installationId of targets(report)){
   if(installationId===homeSiteId)continue;const installation=siteMap.get(installationId);if(!installation)continue;
   if(evaluatedTargets>=MAX_TARGET_COMPARISONS){moreTargets=true;break remoteLoop;}evaluatedTargets++;
   const remote=evidence(report,installationId,current,groups,metadata),{result:similarity,local}=attackSimilarity(locals,remote);
   const level:ExposureLevel=similarity.percent===null?'unavailable':similarity.percent>=70?'high':similarity.percent>0?'partial':'none';
   const confidence:ExposureConfidence=similarity.percent!==null&&local?.complete&&remote.complete&&!workspace.analysis?.truncated?'moderate':'limited';
   const matchedAlerts=local?intersect(local.profile.alerts,remote.profile.alerts).map(briefingTitle):[],matchedBehaviors=local?intersect(local.profile.behaviors,remote.profile.behaviors):[];
   const reasons=[level==='unavailable'?similarity.basis:level==='high'?'Current alerts share a high level of observed evidence. Review both reports to determine whether the activity is related.':level==='partial'?'Some current alert evidence overlaps; the alerts are not established as the same attack.':'Comparable current alert evidence has no measured overlap. This does not establish that your installation is safe.'];
   if(level!=='unavailable')reasons.push(similarity.basis);
   if(matchedAlerts.length)reasons.push('Alert types or specific detection labels match. Matching labels do not confirm a shared attacker.');
   if(matchedBehaviors.length)reasons.push('The same timed behavior rule is independently supported at each installation.');
   comparisons.push({id:report.id+'|'+installationId,reportId:report.id,title:briefingTitle(report.title),installationId,installationName:installation.name,severity:report.severity,level,confidence,reasons,matchedAlerts,matchedBehaviors,localReportIds:local?[local.report.id]:[],synthetic:remote.synthetic,updatedAt:report.updatedAt,similarity});
  }
 }
 comparisons.sort((a,b)=>order[b.level]-order[a.level]||(b.similarity.percent??-1)-(a.similarity.percent??-1)||b.similarity.coverage-a.similarity.coverage||severityRank[b.severity]-severityRank[a.severity]||b.updatedAt.localeCompare(a.updatedAt)||a.id.localeCompare(b.id));
 const visibleComparisons=comparisons.slice(0,50),topSimilarity=visibleComparisons.filter(comparison=>comparison.similarity.percent!==null).sort((a,b)=>b.similarity.percent!-a.similarity.percent!||b.similarity.coverage-a.similarity.coverage||b.updatedAt.localeCompare(a.updatedAt)||a.id.localeCompare(b.id))[0];
 const similarity=topSimilarity?{...topSimilarity.similarity,comparisonId:topSimilarity.id,reportId:topSimilarity.reportId,installationName:topSimilarity.installationName}:null;
 const best=visibleComparisons[0],level=best?.level??'unavailable',confidence=best?.confidence??'limited';
 const summary=(best?.synthetic&&level!=='unavailable'?'Exercise alerts: ':'')+(level==='high'?'Your installation’s current alerts closely match alerts reported at another installation on the globe.':level==='partial'?'Your installation’s current alerts share some observed evidence with alerts at another installation on the globe.':level==='none'?'Current alert evidence can be compared, but no overlap was measured.':!comparisons.length?'No current unresolved reports from other installations are available to compare.':'Add recent current alerts for your installation and another installation to compare their observed activity.');
 const limitations=[
  'Alert Similarity compares current unresolved reports at your installation with current reports at other installations in this app’s globe dataset; it is not worldwide sensor coverage.',
  'The percentage is a fixed-weight evidence index, not a probability, future-attack prediction, or confirmation of the same attacker.',
  'Weights: alert types and specific detection labels 40 points; observed behavior patterns 25; destination ports and protocols 20; source indicators 10; observed outcomes 5. Missing categories earn no points.',
  'Coverage is the total weight of categories present on both sides. A comparable meaningful alert or behavior category is required; eligible zero overlap is 0%, while missing or ineligible evidence is N/A.',
  'Only unresolved reports with evidence from the last 30 days are eligible; resolved reports are excluded. Raw observations require valid recent event timestamps. When only sampled brief facts are available, missing observed time falls back to report update time and limits confidence.',
  'Behavior rules use deduplicated fresh observations from each individual report, installation and source: 5 authentication failures within 10 minutes, 5 destination ports within 10 minutes, or 20 events within 60 seconds.',
  'Ports and protocols are compared as independent facts, not inferred service pairs. Source matching uses public IPs; documentation IPs are allowed only in exercise comparisons. Countries and private addresses earn no source points.',
  'CVEs, affected products, reported priority, and public vulnerability news do not contribute to the alert similarity percentage. Shared service or outcome values alone do not establish related attacks.',
  'Log facts are bounded samples. Missing categories and unobserved behavior do not establish absence of a threat; exercise and operational alerts are kept separate.',
 ];
 if(workspace.analysis?.truncated)limitations.push('The current analysis window omits older events, so some reports may have incomplete sampled log facts.');
 if(observations.length>MAX_OBSERVATIONS)limitations.push(`Behavior analysis uses at most ${MAX_OBSERVATIONS} sampled observations; additional observations are omitted.`);
 if(homeReports.length>MAX_LOCAL_REPORTS)limitations.push(`Comparison uses the ${MAX_LOCAL_REPORTS} most recently updated current local reports of ${homeReports.length}; older local reports are omitted.`);
 if(remoteReports.length>MAX_REMOTE_REPORTS)limitations.push(`Comparison uses the ${MAX_REMOTE_REPORTS} most recently updated current external reports of ${remoteReports.length}; older external reports are omitted.`);
 if(moreTargets)limitations.push(`Evaluation is bounded to ${MAX_TARGET_COMPARISONS} report-installation comparisons; additional targets are omitted.`);
 if(comparisons.length>50)limitations.push(`Showing 50 of ${comparisons.length} comparisons, ordered by similarity level, similarity percentage, and reported priority.`);
 return {homeSiteId,homeName,summary,level,confidence,localActiveReports:homeReports.length,comparisons:visibleComparisons,limitations,updatedAt:now.toISOString(),similarity};
}
