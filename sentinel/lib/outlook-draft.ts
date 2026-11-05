import type {Installation,Incident} from './types';
import {activeFor,severityRank} from './types';
import {dummyPocEmail} from './installations';

const clean=(value:string)=>value.replace(/[\r\n]+/g,' ').trim();
const clip=(value:string,n:number)=>{const chars=Array.from(clean(value));return chars.length>n?chars.slice(0,n-1).join('')+'…':chars.join('');};
const LIMIT=2000;
const encode=(value:string)=>encodeURIComponent(value).replace(/[!'()*]/g,char=>'%'+char.charCodeAt(0).toString(16).toUpperCase());
// Native protocol links use the selected mail handler and keep the click gesture.
// Outlook desktop must be configured as the default handler for mailto.
const compose=(to:string,subject:string,body:string)=>`mailto:${encode(to).replace(/%40/g,'@')}?subject=${encode(subject)}&body=${encode(body)}`;

export function outlookDraft(site:Installation,incidents:Incident[]){
 const savedEmail=site.contactEmail.trim();
 const to=/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(savedEmail)?savedEmail:dummyPocEmail(site.id),dummy=to.endsWith('@example.invalid');
 const reports=activeFor(site.id,incidents).sort((a,b)=>severityRank[b.severity]-severityRank[a.severity]||b.updatedAt.localeCompare(a.updatedAt));
 const subject=`${dummy?'[DEMO] ':''}Sentinel | ${clip(site.name,45)} | ${reports.length} active ${reports.length===1?'alert':'alerts'}${reports.length?' | '+reports[0].severity.toUpperCase():''}`;
 const header=[dummy?'DEMO EMAIL — fictional, non-deliverable recipient. Replace before sending.':'Sentinel alert coordination',`Installation: ${clip(site.name,65)}`,`Active reports: ${reports.length}`,reports.length?'Reported activity is unconfirmed; validate mission impact.':'No active reports are recorded. This does not verify system health.'].join('\r\n');
 const footer='\r\n\r\nPlease confirm impact, response lead, and next update.\r\nFull reports: https://sentinel-incident-globe.ovalllama.chatgpt.site/\r\n';
 const selected:string[]=[];
 const body=(blocks:string[])=>header+(blocks.length?'\r\n\r\n'+blocks.join('\r\n\r\n'):'')+(reports.length>blocks.length?`\r\n${reports.length-blocks.length} additional active report(s); review Sentinel for full details.`:'')+footer;
 const sample=(values:(string|number)[],n=2)=>values.slice(0,n).map(value=>clip(String(value),45)).join(', ');
 for(const report of reports.slice(0,3)){
  const evidence=report.logBriefs?.find(brief=>brief.siteId===site.id);
  const source=evidence?[sample(evidence.sourceIps),sample(evidence.sourceLocations,1)].filter(Boolean).join(' / '):'';
  const destination=evidence?[sample(evidence.targetIps),evidence.targetPorts.length?'ports '+sample(evidence.targetPorts):'',sample(evidence.protocols)].filter(Boolean).join(' / '):'';
  const details=evidence?[
   `Analyzed log sample: ${evidence.analyzedEvents} events`,
   source?`Source: ${source}`:'',destination?`Destination: ${destination}`:'',
   evidence.eventTypes.length?`Events: ${sample(evidence.eventTypes)}`:'',
   evidence.outcomes.length?`Outcomes: ${sample(evidence.outcomes)}`:'',
   evidence.firstSeen?`Observed UTC: ${evidence.firstSeen}${evidence.lastSeen!==evidence.firstSeen?' to '+evidence.lastSeen:''}`:'Log timestamps not provided.',
  ].filter(Boolean):[];
  const log=report.hasLog?`Log: ${clip(report.fileName||'Saved source log',55)}`:evidence?'Evidence: normalized observations':'No source log attached.';
  const variants=[
   [`${report.severity.toUpperCase()} | ${report.status} | ${clip(report.title,60)}`,`Report: ${report.id}`,`Reported: ${report.createdAt}`,`Updated: ${report.updatedAt}`,log,...details,`Summary: ${clip(report.summary,140)}`],
   [`${report.severity.toUpperCase()} | ${report.status} | ${clip(report.title,40)}`,`Report: ${report.id}`,log,...details.filter(line=>!line.startsWith('Events:')&&!line.startsWith('Observed UTC:')),`Summary: ${clip(report.summary,65)}`],
   [`${report.severity.toUpperCase()} | ${report.status} | ${clip(report.title,25)}`,`Report: ${report.id}`,...(source?[`Source: ${source}`]:[]),...(destination?[`Destination: ${destination}`]:[]),`Summary: ${clip(report.summary,35)}`],
  ];
  const block=variants.map(lines=>lines.join('\r\n')).find(value=>compose(to,subject,body([...selected,value])).length<=LIMIT);
  if(!block)break;
  selected.push(block);
 }
 let text=body(selected);
 // Bound long Unicode text while retaining the protected full-report link.
 if(compose(to,subject,text).length>LIMIT){
  const ending='\r\nDetails abbreviated. Full reports: https://sentinel-incident-globe.ovalllama.chatgpt.site/';
  const chars=Array.from(text);
  while(chars.length&&compose(to,subject,chars.join('')+ending).length>LIMIT)chars.pop();
  text=chars.join('')+ending;
 }
 return {to,subject,body:text,url:compose(to,subject,text),dummy,includedReports:selected.length};
}
