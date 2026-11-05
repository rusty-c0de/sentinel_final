'use client';
import {useId,useState} from 'react';
import {ArrowRight,ChevronDown,Info,MapPin,Radar} from 'lucide-react';
import type {AttackSimilarity,ExposureAssessment,ExposureComparison,ExposureLevel} from '../../lib/exposure';

const labels:Record<ExposureLevel,string>={
 high:'Strong Alert Match',
 partial:'Partial Alert Match',
 none:'No Matching Alert Signals',
 unavailable:'Insufficient Alert Data',
};
const confidenceLabel=(confidence:ExposureAssessment['confidence'])=>confidence==='moderate'?'Moderate confidence':'Limited confidence';
const time=(value:string)=>{const date=new Date(value);return Number.isNaN(date.getTime())?'Update time unavailable':date.toLocaleString('en-US',{month:'short',day:'numeric',hour:'numeric',minute:'2-digit',timeZone:'UTC'})+' UTC';};
const number=(value:number)=>Number.isInteger(value)?String(value):value.toFixed(1);
const localBasis=(status:AttackSimilarity['localReportStatus'])=>status==='investigating'?'Active local alert · investigating':status==='reported'?'Active local alert · awaiting review':'No comparable active local alert';
const dimensionLabels={alerts:'Alert Types & Detection Labels',behaviors:'Observed Behaviors',services:'Targeted Services',sources:'Shared Source Indicators',outcomes:'Event Outcomes'};
const alertLabel=(value:string)=>value.replace(/\s*[\[(]?\s*\bCVE-\d{4}-\d{4,10}\b\s*[\])]?\s*/gi,' ').replace(/\s{2,}/g,' ').trim();
const signalLabel=(value:string)=>{const label=alertLabel(value).replace(/^(?:event|detection):/i,'').replace(/_/g,' ').trim();return label?label[0].toUpperCase()+label.slice(1):'';};
const behaviorLabels:Record<string,string>={'AUTH-01':'Repeated failed sign-ins','AUTH-02':'Failed sign-ins with incomplete timing','AUTH-03':'Successful sign-in after repeated failures','NET-01':'Several network services probed','VOL-01':'Concentrated event burst'};

function MatchedSignals({comparison,compact}:{comparison:ExposureComparison;compact:boolean}){
 const alerts=[...new Set(comparison.matchedAlerts.filter(value=>!compact||value.startsWith('event:')).map(signalLabel).filter(Boolean))].slice(0,compact?2:12);
 const behaviors=[...new Set(comparison.matchedBehaviors.map(value=>behaviorLabels[value]??(compact?'Additional matched behavior':value)))].slice(0,compact?3:12);
 if(!alerts.length&&!behaviors.length)return null;
 return <div className="exposure-identifiers" aria-label="Matching alert signals">{alerts.map(alert=><span key={alert}>Alert: {alert}</span>)}{behaviors.map(behavior=><span key={behavior}>Behavior: {behavior}</span>)}</div>;
}

function Similarity({similarity,compact=false,installationName,highest=false}:{similarity:AttackSimilarity;compact?:boolean;installationName:string;highest?:boolean}){
 const available=similarity.percent!==null;
 return <div className={`exposure-similarity ${highest?'exposure-similarity-highest':''} ${available?'':'exposure-similarity-unavailable-state'}`}>
  <div className="exposure-similarity-heading"><span>{highest?'HIGHEST AVAILABLE ALERT SIMILARITY':'ALERT SIMILARITY'}</span>{similarity.synthetic&&<span className="exposure-synthetic">Synthetic Exercise</span>}</div>
  <div className="exposure-similarity-value"><strong>{available?<>{number(similarity.percent!)}<small>%</small></>:'Unavailable'}</strong><div><span>{number(similarity.coverage)}% data coverage</span><span>{localBasis(similarity.localReportStatus)}</span></div></div>
  {highest&&<p className="exposure-similarity-installation">Compared with <strong>{installationName}</strong></p>}
  {highest&&<p className="exposure-similarity-basis">Highest score among the displayed comparisons.</p>}
  {available?<div className="exposure-similarity-meter" role="meter" aria-label={`Alert similarity with ${installationName}`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={similarity.percent!} aria-valuetext={`${number(similarity.percent!)} percent alert similarity; ${number(similarity.coverage)} percent data coverage.`}><span style={{width:`${similarity.percent}%`}}/></div>:<p className="exposure-similarity-unavailable">A score requires comparable current alert data at your installation and another installation.</p>}
  <p className="exposure-similarity-basis">{similarity.basis}</p>
  {!compact&&similarity.localReportId&&<p className="exposure-similarity-reference">Compared local alert report: <code>{similarity.localReportId}</code></p>}
  <details className="exposure-similarity-breakdown"><summary>How Alert Similarity Is Calculated</summary><p>This fixed 100-point index compares one active local alert report with one active report from another installation.</p><table><caption>Current alert overlap by category</caption><thead><tr><th>Category</th><th>Points</th><th>Matched Data</th></tr></thead><tbody>{similarity.breakdown.map(dimension=><tr key={dimension.key}><th scope="row">{dimensionLabels[dimension.key]}</th><td>{number(dimension.points)} / {dimension.weight}</td><td>{dimension.percent===null?'Missing comparable data':`${dimension.matched} / ${dimension.total} shared values · ${number(dimension.percent)}% overlap`}</td></tr>)}</tbody></table><p>Weights: alert types and detection labels 40, observed behaviors 25, targeted services 20, source indicators 10, outcomes 5. Each overlap is the number of shared values divided by all distinct values. Missing categories add zero points; the result is not rescaled. Coverage counts only categories with data on both sides.</p></details>
 </div>;
}

export default function AttackExposure({assessment,compact=false,onSelectInstallation}:{assessment:ExposureAssessment;compact?:boolean;onSelectInstallation?:(id:string)=>void}){
 const [showAll,setShowAll]=useState(false);
 const headingId=useId(),listId=useId(),limit=compact?2:3;
 const comparisons=showAll?assessment.comparisons:assessment.comparisons.slice(0,limit);
 return <section className={`exposure-panel ${compact?'exposure-compact':''}`} aria-labelledby={headingId}>
  <header className="exposure-heading"><div><p className="exposure-eyebrow"><Radar size={13}/> MY INSTALLATION · CURRENT ALERT COMPARISON</p><h2 id={headingId}>Current Alert Comparison for {assessment.homeName}</h2><p className="exposure-intro">Compare your base’s current alerts with uploaded active alert reports at other installations shown on the globe.</p></div><div className="exposure-local-count"><strong>{assessment.localActiveReports}</strong><span>active local alert {assessment.localActiveReports===1?'report':'reports'}</span></div></header>
  {assessment.similarity?<div className="exposure-similarity-overview"><Similarity similarity={assessment.similarity} installationName={assessment.similarity.installationName} highest compact={compact}/></div>:<div className="exposure-similarity-no-score"><span>HIGHEST AVAILABLE ALERT SIMILARITY</span><strong>Unavailable</strong><p>No pair of current local and external alert reports has enough comparable alert data for a numeric index.</p></div>}
  <div className={`exposure-summary exposure-level-${assessment.level}`}><Radar size={21}/><div><div className="exposure-summary-meta"><strong>{labels[assessment.level]}</strong><span>{confidenceLabel(assessment.confidence)}</span></div><p>{assessment.summary}</p></div></div>
  {!assessment.localActiveReports&&<p className="exposure-coverage-note"><Info size={14}/><span>No active local alert reports are available to compare. Add or refresh your installation’s current alert logs.</span></p>}
  <div className="exposure-comparisons" id={listId}>
   {comparisons.map(comparison=><article className={`exposure-comparison exposure-level-${comparison.level}`} key={comparison.id}>
    <div className="exposure-comparison-meta"><span><MapPin size={13}/>{comparison.installationName}</span><span className={`exposure-severity exposure-severity-${comparison.severity}`}>{comparison.severity} priority</span>{comparison.synthetic&&<span className="exposure-synthetic">Synthetic Exercise</span>}</div>
    <h3>{alertLabel(comparison.title)||'Active Alert Report'}</h3>
    <Similarity similarity={comparison.similarity} installationName={comparison.installationName} compact={compact}/>
    <div className="exposure-comparison-status"><strong>{labels[comparison.level]}</strong><span>{confidenceLabel(comparison.confidence)}</span></div>
    <ul className="exposure-reasons">{comparison.reasons.map((reason,index)=><li key={index}>{reason}</li>)}</ul>
    <MatchedSignals comparison={comparison} compact={compact}/>
    {!compact&&comparison.localReportIds.length>0&&<details className="exposure-local-references"><summary>Supporting Local Alert Reports ({comparison.localReportIds.length})</summary><ul>{comparison.localReportIds.map(id=><li key={id}><code>{id}</code></li>)}</ul></details>}
    <footer><span>Updated {time(comparison.updatedAt)}</span>{onSelectInstallation&&<button type="button" onClick={()=>onSelectInstallation(comparison.installationId)}>View Installation <ArrowRight size={13}/></button>}</footer>
   </article>)}
   {!assessment.comparisons.length&&<div className="exposure-empty"><Radar size={24}/><h3>No Active External Alerts to Compare</h3><p>Comparisons use active alert reports uploaded for other installations on the globe.</p></div>}
  </div>
  {assessment.comparisons.length>limit&&<button type="button" className="exposure-show-more" onClick={()=>setShowAll(value=>!value)} aria-expanded={showAll} aria-controls={listId}>{showAll?'Show Fewer Comparisons':`Show All ${assessment.comparisons.length} Comparisons`}<ChevronDown size={14} className={showAll?'exposure-expanded':''}/></button>}
  <div className="exposure-method-note"><Info size={14}/><p>Alert Similarity measures overlap in current uploaded alert data. A missing score means the reports cannot be compared, rather than a zero match.</p></div>
  {assessment.limitations.length>0&&<details className="exposure-limitations"><summary>Comparison Data &amp; Limits</summary><ul>{assessment.limitations.map((limitation,index)=><li key={index}>{limitation}</li>)}</ul><p>Updated {time(assessment.updatedAt)}. Comparisons refresh with workspace data.</p></details>}
 </section>;
}
