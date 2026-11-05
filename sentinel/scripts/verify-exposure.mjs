// Isolated checks for home-base affiliation and evidence-based attack comparison.
import {strict as assert} from 'node:assert';
import {copyFileSync,mkdtempSync,readFileSync,readdirSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import ts from 'typescript';

const directory=mkdtempSync(join(tmpdir(),'sentinel-exposure-'));
try{
 const modules=['api','ingest','analysis','geo','parser','types','demo','installations','threat-intel','intel-types','commander','outlook-draft','report-evidence','home-base','attack-metadata','exposure'];
 for(const name of modules){
  const source=readFileSync(resolve('lib',name+'.ts'),'utf8').replaceAll('import.meta.env.DEV','false');
  const compiled=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText
   .replace(/from (['"])\.\/([\w-]+)\1/g,(_,quote,module)=>`from './${module}.mjs'`)
   .replace("from './countries.json'","from './countries.json' with {type:'json'}");
  writeFileSync(join(directory,name+'.mjs'),compiled);
 }
 copyFileSync(resolve('lib/countries.json'),join(directory,'countries.json'));
 const {APPROVED_INSTALLATIONS}=await import(join(directory,'installations.mjs'));
 const {ingestLog}=await import(join(directory,'ingest.mjs'));
 const {buildAttackMetadata,readAttackMetadata}=await import(join(directory,'attack-metadata.mjs'));
 const {buildExposureAssessment}=await import(join(directory,'exposure.mjs'));
 const {api}=await import(join(directory,'api.mjs'));
 const {HOME_INSTALLATION_ID,HOME_MEMBERSHIP}=await import(join(directory,'home-base.mjs'));
 const home='patrick-space-force-base',remote='naval-station-norfolk',other='quantico';
 assert.equal(HOME_INSTALLATION_ID,home);assert.equal(HOME_MEMBERSHIP.installationId,home);
 const now=new Date('2026-11-05T12:00:00.000Z'),date='2026-11-05T11:00:00.000Z';
 const sites=APPROVED_INSTALLATIONS.map(site=>({...site,contactName:'',contactEmail:'',contactPhone:'',createdAt:date,updatedAt:date}));
 const indicators=(cves=[],signatures=[],synthetic=false)=>({cves,signatures,products:[],synthetic});
 const metadata=(siteId,cves=[],signatures=[],synthetic=false,source='log')=>({version:1,source,targets:[{siteId,...indicators(cves,signatures,synthetic)}]});
 const brief=(siteId,sourceIp='8.8.8.8')=>({siteId,analyzedEvents:6,sourceIps:[sourceIp],sourceLocations:['Russia'],targetIps:['10.0.0.1'],targetPorts:[443],protocols:['TCP'],eventTypes:['authentication'],outcomes:['failure'],firstSeen:date,lastSeen:date});
 const report=(id,siteId,extra={})=>({id,siteId,title:'Submitted alert',summary:'Requires review.',severity:'high',status:'reported',hasLog:true,fileName:id+'.json',createdAt:date,updatedAt:date,targetSiteIds:[siteId],logBriefs:[brief(siteId)],attackMetadata:metadata(siteId),...extra});
 const workspace=incidents=>({sites,incidents,updatedAt:date,membership:HOME_MEMBERSHIP});
 const compare=(incidents,observations=[])=>buildExposureAssessment(workspace(incidents),home,now,observations);
 const pair=(localExtra={},remoteExtra={})=>[report('local',home,localExtra),report('remote',remote,remoteExtra)];
 const currentCve='CVE-2024-3400';


 // Current threat patterns, rather than vulnerability names, drive this index.
 const signature='VENDOR-AUTH-BRUTEFORCE-v2';
 const emptyBrief=siteId=>({...brief(siteId),sourceIps:[],targetPorts:[],protocols:[],eventTypes:[],outcomes:[]});
 const row=(similarity,key)=>similarity.breakdown.find(value=>value.key===key);
 const observation=(incidentId,siteId,index,extra={})=>({id:incidentId+'-event-'+index,incidentId,siteId,sourceIp:'8.8.8.8',targetIp:'10.0.0.1',targetPort:443,protocol:'TCP',username:'fixture-user',eventType:'authentication',outcome:'failure',occurredAt:new Date(Date.parse(date)+index*1000).toISOString(),sourceLabel:'Fixture source',sourceLat:null,sourceLng:null,precision:'unknown',lineNumber:index+1,createdAt:date,...extra});
 const observed=(incidentId,siteId,count=6,extra={})=>Array.from({length:count},(_,index)=>observation(incidentId,siteId,index,extra));
 const fullRecords=pair({attackMetadata:metadata(home,[],[signature])},{attackMetadata:metadata(remote,[],[signature])});
 const fullObservations=[...observed('local',home),...observed('remote',remote)];
 const similarityFor=(incidents,observations=[],id='remote',siteId=remote)=>compare(incidents,observations).comparisons.find(item=>item.reportId===id&&item.installationId===siteId).similarity;
 const complete=compare(fullRecords,fullObservations),full=complete.comparisons[0].similarity;
 assert.equal(complete.level,'high');assert.equal(full.percent,100);assert.equal(full.coverage,100);assert.equal(full.localReportId,'local');
 assert.deepEqual(Object.fromEntries(full.breakdown.map(item=>[item.key,[item.weight,item.points]])),{alerts:[40,40],behaviors:[25,25],services:[20,20],sources:[10,10],outcomes:[5,5]});
 assert(complete.comparisons[0].matchedBehaviors.includes('AUTH-01'));assert(complete.comparisons[0].matchedAlerts.some(value=>value.includes('authentication')));
 assert.equal(Object.hasOwn(complete.comparisons[0],'matchedCves'),false);assert.equal(Object.hasOwn(complete.comparisons[0],'matchedSignatures'),false);
 assert.equal(Object.hasOwn(complete,'probability'),false);assert(!JSON.stringify(complete).includes('8.8.8.8'),'Summaries expose no raw addresses');

 // A shared CVE alone cannot make a threat comparable; meaningful current
 // alert categories can be compared even when no vulnerability is supplied.
 const cveOnly=pair({attackMetadata:metadata(home,[currentCve]),logBriefs:[emptyBrief(home)]},{attackMetadata:metadata(remote,[currentCve]),logBriefs:[emptyBrief(remote)]});
 assert.equal(similarityFor(cveOnly).percent,null);assert.equal(compare(cveOnly).level,'unavailable');
 const onlyAlerts=pair({attackMetadata:metadata(home),logBriefs:[{...emptyBrief(home),eventTypes:['credential_access']}]},{attackMetadata:metadata(remote),logBriefs:[{...emptyBrief(remote),eventTypes:['credential_access']}]});
 assert.equal(similarityFor(onlyAlerts).percent,40);assert.equal(similarityFor(onlyAlerts).coverage,40);
 const differentAlerts=pair({attackMetadata:metadata(home),logBriefs:[{...emptyBrief(home),eventTypes:['credential_access']}]},{attackMetadata:metadata(remote),logBriefs:[{...emptyBrief(remote),eventTypes:['lateral_movement']}]});
 assert.equal(similarityFor(differentAlerts).percent,0);assert.equal(similarityFor(differentAlerts).coverage,40);assert.equal(compare(differentAlerts).level,'none');
 const generic=pair({logBriefs:[{...brief(home),eventTypes:['network_event']}]},{logBriefs:[{...brief(remote),eventTypes:['manual_observation']}]});
 assert.equal(similarityFor(generic).percent,null,'Generic geography, severity, service, source and outcome overlap do not establish a comparable alert');
 const altered=fullRecords.map((incident,index)=>({...incident,attackMetadata:{...incident.attackMetadata,targets:incident.attackMetadata.targets.map(target=>({...target,cves:index?['CVE-2021-44228']:['CVE-2024-3400'],products:index?['Other Product']:['PAN-OS']}))}}));
 assert.deepEqual(compare(altered,fullObservations),complete,'Changing CVEs and products never changes score, coverage, levels or ordering');
 const rankedRecords=[...fullRecords,report('different-threat',other,{attackMetadata:metadata(other,[],['VENDOR-OTHER-ALERT'])})];
 const changedRanking=rankedRecords.map((incident,index)=>({...incident,attackMetadata:{...incident.attackMetadata,targets:incident.attackMetadata.targets.map(target=>({...target,cves:[index%2?currentCve:'CVE-2021-44228'],products:['Unrelated Product '+index]}))}}));
 assert.deepEqual(compare(changedRanking,fullObservations),compare(rankedRecords,fullObservations),'Unrelated vulnerability metadata cannot reorder the global alert comparisons');
 const fallback=readAttackMetadata(null,'Reported '+currentCve,'Submitted claim, not validated.',home);
 assert.equal(fallback.source,'report-text');assert.deepEqual(fallback.targets.map(target=>target.siteId),[home]);assert.deepEqual(fallback.targets[0].cves,[currentCve]);
 assert.equal(similarityFor(pair({attackMetadata:fallback,logBriefs:[emptyBrief(home)]},{attackMetadata:metadata(remote,[currentCve]),logBriefs:[emptyBrief(remote)]})).percent,null);

 // Jaccard uses unique dimension tokens and a fixed 100-point denominator.
 // Services are independent port and protocol tokens, never inferred pairs.
 const partial=similarityFor(pair(
  {attackMetadata:metadata(home,[],['VENDOR-SHARED-ALERT','VENDOR-LOCAL-ALERT']),logBriefs:[{...emptyBrief(home),sourceIps:['8.8.8.8','1.1.1.1'],targetPorts:[443,22],protocols:['TCP'],outcomes:['failure','success']}]},
  {attackMetadata:metadata(remote,[],['VENDOR-SHARED-ALERT','VENDOR-REMOTE-ALERT']),logBriefs:[{...emptyBrief(remote),sourceIps:['8.8.8.8','9.9.9.9'],targetPorts:[443],protocols:['TCP'],outcomes:['failure','blocked']}]},
 ));
 assert.equal(partial.percent,32);assert.equal(partial.coverage,75);assert.equal(row(partial,'services').matched,2);assert.equal(row(partial,'services').total,3);
 const sourceRange=count=>Array.from({length:count},(_,index)=>'8.8.8.'+(index+1));
 const preciseRounding=similarityFor(pair(
  {attackMetadata:metadata(home,[],['VENDOR-LOCAL-ONLY']),logBriefs:[{...emptyBrief(home),sourceIps:sourceRange(8),targetPorts:[22,23,24],protocols:['TCP'],outcomes:['failure','success','blocked']}]},
  {attackMetadata:metadata(remote,[],['VENDOR-REMOTE-ONLY']),logBriefs:[{...emptyBrief(remote),sourceIps:sourceRange(9),targetPorts:[443,444,445],protocols:['TCP'],outcomes:['failure','success','blocked','allowed']}]},
 ));
 assert.equal(preciseRounding.percent,15,'Round the raw weighted total once: 20/7 + 10*(8/9) + 5*(3/4) = 15.496; adding rounded display points would incorrectly yield 16');
 const serviceTokens=similarityFor(pair(
  {logBriefs:[{...brief(home),targetPorts:[443,53],protocols:['TCP','UDP']}]},
  {logBriefs:[{...brief(remote),targetPorts:[443],protocols:['TCP']}]},
 ));
 assert.equal(row(serviceTokens,'services').matched,2);assert.equal(row(serviceTokens,'services').total,4);assert.equal(row(serviceTokens,'services').points,10,'A summary with multiple ports/protocols must not invent exact port/protocol combinations');
 const missingDimensions=similarityFor(pair({logBriefs:[{...emptyBrief(home),eventTypes:['authentication']}]},{logBriefs:[{...brief(remote)}]}));
 assert.equal(missingDimensions.percent,40);assert.equal(missingDimensions.coverage,40,'Missing evidence earns no points and is not renormalized');
 const duplicateRecords=fullRecords.map(item=>({...item,attackMetadata:{...item.attackMetadata,targets:item.attackMetadata.targets.map(target=>({...target,signatures:[...target.signatures,...target.signatures]}))},logBriefs:item.logBriefs.map(value=>({...value,eventTypes:[...value.eventTypes,...value.eventTypes],targetPorts:[...value.targetPorts,...value.targetPorts],protocols:[...value.protocols,...value.protocols],outcomes:[...value.outcomes,...value.outcomes],sourceIps:[...value.sourceIps,...value.sourceIps]}))}));
 assert.equal(similarityFor(duplicateRecords,[...fullObservations,...fullObservations]).percent,full.percent);assert.equal(similarityFor(duplicateRecords,fullObservations).coverage,full.coverage);

 // Both sides must represent current, unresolved reports. Report or event
 // timing that is stale, invalid or future dated cannot imply current safety.
 const old='2026-08-01T10:00:00.000Z',future='2026-11-06T11:00:00.000Z';
 for(const stale of [old,future,'invalid']){
  const records=fullRecords.map((item,index)=>index?item:{...item,updatedAt:date,logBriefs:[{...brief(home),lastSeen:stale}]});
  assert.equal(similarityFor(records,fullObservations).percent,null);
 }
 assert.equal(similarityFor(fullRecords.map((item,index)=>index?item:{...item,createdAt:'',updatedAt:'',logBriefs:[{...brief(home),firstSeen:null,lastSeen:null}]}),fullObservations).percent,null);
 const resolvedLocal=compare(fullRecords.map((item,index)=>index?item:{...item,status:'resolved'}),fullObservations);
 assert.equal(resolvedLocal.localActiveReports,0);assert.equal(resolvedLocal.comparisons[0].similarity.percent,null);assert.equal(resolvedLocal.similarity,null);assert.deepEqual(resolvedLocal.comparisons[0].localReportIds,[]);
 assert.equal(compare(fullRecords.map((item,index)=>index?{...item,status:'resolved'}:item),fullObservations).comparisons.length,0);
 assert.equal(compare([]).level,'unavailable');assert.equal(compare([fullRecords[0]]).comparisons.length,0);
 assert.equal(similarityFor([fullRecords[1]],observed('remote',remote)).percent,null);

 // Behavioral rules use fresh, independent observations from the selected
 // report and target, rather than workspace-wide aggregate pattern labels.
 for(const invalidTime of [old,future,null,'invalid']){
  const events=fullObservations.map(event=>event.incidentId==='local'?{...event,occurredAt:invalidTime}:event);
  const value=similarityFor(fullRecords,events);assert.equal(row(value,'behaviors').percent,null);assert.equal(value.percent,null,'A supplied raw group with no fresh usable observations cannot fall back to a fresh summary');
 }
 const duplicates=[...Array(6).fill(observation('local',home,0)),...observed('remote',remote)];
 assert.equal(row(similarityFor(fullRecords,duplicates),'behaviors').percent,null,'Repeating one observation cannot manufacture a burst');
 const partlyStale=fullObservations.map(event=>event.incidentId==='local'&&event.lineNumber>4?{...event,occurredAt:old}:event);
 assert.equal(row(similarityFor(fullRecords,partlyStale),'behaviors').percent,null,'Stale rows cannot complete a fresh authentication threshold');
 const splitSources=fullObservations.map(event=>event.incidentId==='local'&&event.lineNumber>3?{...event,sourceIp:'1.1.1.1'}:event);
 assert.equal(row(similarityFor(fullRecords,splitSources),'behaviors').percent,null,'Different sources cannot be pooled into one source-specific rule');
 const splitReports=[report('local-a',home,{attackMetadata:metadata(home,[],[signature])}),report('local-b',home,{attackMetadata:metadata(home,[],[signature])}),fullRecords[1]];
 const splitEvents=[...observed('local-a',home,3),...observed('local-b',home,3),...observed('remote',remote)];
 assert.equal(row(similarityFor(splitReports,splitEvents),'behaviors').percent,null,'Failures from independent reports cannot be pooled into one qualifying report');
 const resolvedEvents=[...fullObservations.filter(event=>event.incidentId!=='local'),...observed('resolved-local',home),...observed('local',home,1)];
 assert.equal(row(similarityFor([...fullRecords,report('resolved-local',home,{status:'resolved'})],resolvedEvents),'behaviors').percent,null);
 const wrongTarget=fullObservations.map(event=>event.incidentId==='local'?{...event,siteId:other}:event);
 assert.equal(row(similarityFor(fullRecords,wrongTarget),'behaviors').percent,null,'A different target installation cannot supply local behavior');
 const noAlerts=pair({attackMetadata:metadata(home),logBriefs:[{...brief(home),eventTypes:['network_event']}]},{attackMetadata:metadata(remote),logBriefs:[{...brief(remote),eventTypes:['network_event']}]});
 const volume=[...observed('local',home,20,{eventType:'network_event'}),...observed('remote',remote,20,{eventType:'network_event'})];
 const behaviorOnly=similarityFor(noAlerts,volume);assert.equal(behaviorOnly.percent,60);assert.equal(behaviorOnly.coverage,60);assert.equal(row(behaviorOnly,'behaviors').points,25,'A qualifying fresh event burst permits a behavior-based comparison without CVEs or meaningful alert types');

 // Operational correlation uses public source indicators. Exercise evidence
 // can compare documentation addresses, and cannot mix with operational data.
 const documentationRecords=fullRecords.map(item=>({...item,logBriefs:[brief(item.siteId,'203.0.113.10')]}));
 const documentationEvents=fullObservations.map(event=>({...event,sourceIp:'203.0.113.10'}));
 const operationalReserved=similarityFor(documentationRecords,documentationEvents);assert.equal(operationalReserved.percent,90);assert.equal(operationalReserved.coverage,90);assert.equal(row(operationalReserved,'sources').percent,null);
 const syntheticRecords=documentationRecords.map(item=>({...item,attackMetadata:{...item.attackMetadata,targets:item.attackMetadata.targets.map(target=>({...target,synthetic:true}))}}));
 assert.equal(similarityFor(syntheticRecords,documentationEvents).percent,100);
 const mixedSynthetic=syntheticRecords.map((item,index)=>index?item:{...item,attackMetadata:metadata(home,[],[signature],false)});
 assert.equal(similarityFor(mixedSynthetic,documentationEvents).percent,null);
 const redacted=compare(fullRecords.map((item,index)=>index?{...item,title:'Source 203.0.113.77 and [2001:db8::77]'}:item),fullObservations);
 assert(!JSON.stringify(redacted).includes('203.0.113.77'));assert(!JSON.stringify(redacted).includes('2001:db8::77'));

 // Linked targets keep their own alert and behavioral evidence.
 const linked=report('remote',remote,{targetSiteIds:[remote,other],attackMetadata:{version:1,source:'log',targets:[{siteId:remote,...indicators([],['VENDOR-OTHER-ALERT'])},{siteId:other,...indicators([],[signature])}]},logBriefs:[{...brief(remote),eventTypes:['lateral_movement']},brief(other)]});
 const scopedRecords=[fullRecords[0],linked];
 const scopedEvents=fullObservations.map(event=>event.incidentId==='remote'?{...event,eventType:'lateral_movement'}:event);
 assert.equal(row(similarityFor(scopedRecords,scopedEvents,'remote',remote),'alerts').points,0);
 assert.equal(row(similarityFor(scopedRecords,scopedEvents,'remote',other),'alerts').points,40);
 assert.equal(row(similarityFor(scopedRecords,scopedEvents,'remote',other),'behaviors').percent,null,'A linked target cannot inherit the primary target’s raw behavior');
 const selfMetadata=metadata(home,[],[signature]);selfMetadata.targets.push({...selfMetadata.targets[0],siteId:remote});
 const selfReport=report('one-multi-target-report',home,{targetSiteIds:[home,remote],attackMetadata:selfMetadata,logBriefs:[brief(home),brief(remote)]});
 const self=compare([selfReport],[...observed(selfReport.id,home),...observed(selfReport.id,remote)]);
 assert.equal(self.comparisons[0].similarity.percent,null);assert.equal(self.similarity,null,'An independent local report is required; a report cannot compare with itself');

 // Choose one best local report, rather than merging complementary local
 // evidence into a fictitious perfect match.
 const singlePairRecords=[
  report('pair-a',home,{attackMetadata:metadata(home,[],[signature]),logBriefs:[{...brief(home,'1.1.1.1'),targetPorts:[22],protocols:['UDP'],outcomes:['success']}]}),
  report('pair-b',home,{attackMetadata:metadata(home,[],['VENDOR-OTHER-ALERT']),logBriefs:[{...brief(home),eventTypes:['network_event'],targetPorts:[443,444,445,446,447]}]}),
  fullRecords[1],
 ];
 const singlePairEvents=[...observed('pair-a',home,5,{sourceIp:'1.1.1.1',protocol:'UDP',eventType:'network_event',outcome:'success'}).map((event,index)=>({...event,targetPort:22+index})),...observed('remote',remote,5,{eventType:'network_event'}).map((event,index)=>({...event,targetPort:443+index}))];
 const bestPair=similarityFor(singlePairRecords,singlePairEvents);assert.equal(bestPair.percent,65);assert.equal(bestPair.localReportId,'pair-a');assert.equal(similarityFor(singlePairRecords.slice().reverse(),singlePairEvents).localReportId,'pair-a');

 // Large workspaces remain bounded while exposing the full active local count.
 const manyLocals=Array.from({length:400},(_,index)=>report('local-many-'+String(index).padStart(3,'0'),home,{logBriefs:[emptyBrief(home)]}));
 const omittedLocal={...fullRecords[0],id:'older-local-match',updatedAt:'2026-11-04T11:00:00.000Z'};
 const remoteMatch={...fullRecords[1],id:'remote-match'};
 const boundedLocal=compare([...manyLocals,omittedLocal,remoteMatch],[...observed(omittedLocal.id,home),...observed(remoteMatch.id,remote)]);
 assert.equal(boundedLocal.localActiveReports,401);assert.equal(boundedLocal.level,'unavailable');assert(boundedLocal.limitations.some(line=>/older local reports are omitted/i.test(line)));
 const manyRemote=Array.from({length:300},(_,index)=>report('remote-many-'+String(index).padStart(3,'0'),remote,{targetSiteIds:[remote,other],logBriefs:[emptyBrief(remote)]}));
 const recentMatch={...fullRecords[1],id:'recent-remote-match',updatedAt:'2026-11-05T11:59:00.000Z'};
 const boundedEvents=[...observed('local',home),...observed(recentMatch.id,remote)];
 const boundedRecords=[fullRecords[0],...manyRemote,recentMatch];
 const boundedRemote=compare(boundedRecords,boundedEvents),reversed=compare(boundedRecords.slice().reverse(),boundedEvents.slice().reverse());
 assert.equal(boundedRemote.level,'high');assert.equal(boundedRemote.comparisons[0].reportId,recentMatch.id);assert(boundedRemote.comparisons.length<manyRemote.length);
 assert(boundedRemote.limitations.some(line=>/older external reports are omitted/i.test(line)));assert(boundedRemote.limitations.some(line=>/additional targets are omitted/i.test(line)));assert(boundedRemote.limitations.some(line=>/Showing .* comparisons/i.test(line)));
 assert.deepEqual(reversed.comparisons.map(item=>item.id),boundedRemote.comparisons.map(item=>item.id));assert.deepEqual(reversed.similarity,boundedRemote.similarity);
 assert(boundedRemote.comparisons.some(item=>item.id===boundedRemote.similarity.comparisonId));
 for(const records of [fullRecords,singlePairRecords,generic])for(const comparison of compare(records).comparisons){
  assert.equal(Object.hasOwn(comparison,'probability'),false);
  if(comparison.similarity.percent!==null){assert(Number.isInteger(comparison.similarity.percent));assert(comparison.similarity.percent>=0&&comparison.similarity.percent<=comparison.similarity.coverage&&comparison.similarity.coverage<=100);}
 }

 // Parser fields survive supported input formats without assigning one target's CVE to another.
 const json=JSON.stringify({synthetic:true,cve_id:currentCve,affected_product:'PAN-OS',events:[
  {source_ip:'203.0.113.10',target_installation:'Patrick SFB',detection_signature:'VENDOR-PANOS-EXPLOIT-3400'},
  {source_ip:'203.0.113.11',target_installation:'Naval Station Norfolk',cve_id:'CVE-2021-44228',detection_signature:'VENDOR-LOG4J-44228'},
 ]});
 const ingested=ingestLog(json);assert.equal(ingested.events.length,2);
 assert.deepEqual(ingested.events[0].attack.cves,[currentCve]);assert.deepEqual(ingested.events[1].attack.cves,['CVE-2021-44228']);
 assert.equal(ingested.events[0].attack.synthetic,true);assert(ingested.events[0].attack.products.some(product=>product.toLowerCase()==='pan-os'));
 const mapped=ingested.events.map((event,index)=>({...event,siteId:index?remote:home}));
 const perTarget=buildAttackMetadata(mapped,home,'Submitted CVE report','');
 assert.deepEqual(perTarget.targets.find(target=>target.siteId===home).cves,[currentCve]);
 assert.deepEqual(perTarget.targets.find(target=>target.siteId===remote).cves,['CVE-2021-44228']);
 const csv=ingestLog('source_ip,cve_id,detection_signature,affected_product,synthetic\n203.0.113.10,CVE-2024-3400,VENDOR-PANOS-EXPLOIT-3400,PAN-OS,true\n');
 assert.deepEqual(csv.events[0].attack.cves,[currentCve]);assert.equal(csv.events[0].attack.synthetic,true);
 const kv=ingestLog('src=203.0.113.10 cve_id=CVE-2024-3400 detection_signature=VENDOR-PANOS-EXPLOIT-3400 affected_product=PAN-OS synthetic=true');
 assert.deepEqual(kv.events[0].attack.cves,[currentCve]);assert(kv.events[0].attack.signatures.some(signature=>signature.toUpperCase()==='VENDOR-PANOS-EXPLOIT-3400'));
 const signatureArray=ingestLog(JSON.stringify({source_ip:'203.0.113.15',detection_signatures:['VENDOR-SHARED-EXPLOIT','VENDOR-LOCAL-ONLY'],affected_products:['Example Service A','Example Service B']})).events[0].attack;
 const remoteSignatureArray=ingestLog(JSON.stringify({source_ip:'203.0.113.16',detection_signatures:['VENDOR-SHARED-EXPLOIT','VENDOR-REMOTE-ONLY'],affected_products:['Example Service A','Example Service C']})).events[0].attack;
 assert.deepEqual(signatureArray.signatures,['vendor-shared-exploit','vendor-local-only']);assert.deepEqual(signatureArray.products,['example service a','example service b']);
 const arrayComparison=compare(pair({attackMetadata:buildAttackMetadata([{siteId:home,attack:signatureArray}],home,'Array labels','')},{attackMetadata:buildAttackMetadata([{siteId:remote,attack:remoteSignatureArray}],remote,'Array labels','')}));
 assert(arrayComparison.comparisons[0].matchedAlerts.includes('detection:vendor-shared-exploit'));


 // The actual API persists compact evidence and keeps home affiliation server-owned.
 const db=new DatabaseSync(':memory:');
 for(const file of readdirSync('drizzle').filter(file=>file.endsWith('.sql')).sort())db.exec(readFileSync(join('drizzle',file),'utf8'));
 class Statement{
  constructor(sql){this.sql=sql;this.args=[];}
  bind(...args){this.args=args;return this;}
  async first(){return db.prepare(this.sql).get(...this.args)??null;}
  async all(){return {results:db.prepare(this.sql).all(...this.args)};}
  async run(){const result=db.prepare(this.sql).run(...this.args);return {success:true,meta:{changes:Number(result.changes)}};}
 }
 const files=new Map();
 const env={SITE_PASSWORD:'isolated-exposure-team',COMMANDER_PASSWORD:'isolated-exposure-command',DB:{prepare:sql=>new Statement(sql),batch:async statements=>{db.exec('BEGIN');try{const results=[];for(const statement of statements)results.push(/^SELECT/i.test(statement.sql)?await statement.all():await statement.run());db.exec('COMMIT');return results;}catch(error){db.exec('ROLLBACK');throw error;}}},BUCKET:{put:async(key,value)=>files.set(key,value),get:async key=>files.has(key)?{body:files.get(key)}:null,delete:async keys=>(Array.isArray(keys)?keys:[keys]).forEach(key=>files.delete(key))}};
 const origin='https://sentinel-exposure.test';let cookie='';
 const call=(path,method='GET',body,withCookie=cookie)=>api(new Request(origin+path,{method,headers:{'Content-Type':'application/json',Origin:origin,Cookie:withCookie},...(body===undefined?{}:{body:JSON.stringify(body)})}),env);
 assert.equal((await call('/api/workspace')).status,401);
 assert.equal((await call('/api/login','POST',{password:env.SITE_PASSWORD,homeSiteId:remote,membership:{installationId:remote}})).status,400);
 const login=await call('/api/login','POST',{password:env.SITE_PASSWORD});assert.equal(login.status,200);cookie=login.headers.get('set-cookie').split(';')[0];
 const session=await(await call('/api/session')).json();assert.equal(session.authenticated,true);assert.equal(session.membership.installationId,home);
 assert.equal((await call('/api/membership','POST',{installationId:remote})).status,405);
 const current=new Date().toISOString();
 const saveReport=async(siteId,cve,extra={})=>{
  const rawLog=JSON.stringify({cve_id:cve,affected_product:'Example service',detection_signature:'VENDOR-AUTH-BRUTEFORCE-v2',events:Array.from({length:6},(_,index)=>({timestamp:new Date(Date.parse(current)-index*1000).toISOString(),source_ip:'203.0.113.74',source_country:'China',destination_ip:'10.0.0.1',destination_port:443,protocol:'TCP',event_type:'authentication',outcome:'failure',target_installation:sites.find(site=>site.id===siteId).name}))});
  const response=await call('/api/reports','POST',{siteId,title:'Reported '+cve,summary:'Isolated fixture evidence.',severity:'high',status:'reported',rawLog,reviewed:true,...extra});assert.equal(response.status,201,await response.clone().text());return (await response.json()).incidentId;
 };
 const localId=await saveReport(home,currentCve),remoteId=await saveReport(remote,currentCve),otherId=await saveReport(other,'CVE-2021-44228');
 const multiRaw=JSON.stringify({events:[{timestamp:current,source_ip:'203.0.113.75',cve_id:currentCve,target_installation:'Patrick SFB'},{timestamp:current,source_ip:'203.0.113.76',cve_id:'CVE-2021-44228',target_installation:'Naval Station Norfolk'}]});
 const multiResponse=await call('/api/reports','POST',{siteId:home,title:'Multiple targets',summary:'Separate scoped indicators.',severity:'critical',status:'reported',rawLog:multiRaw,reviewed:true});assert.equal(multiResponse.status,201,await multiResponse.clone().text());const multiId=(await multiResponse.json()).incidentId;
 const legacyId=crypto.randomUUID();db.prepare('INSERT INTO incidents (id,site_id,title,summary,severity,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)').run(legacyId,home,'Older report '+currentCve,'Preserved original record.','low','reported',current,current);
 const state=await(await call('/api/workspace')).json();assert.equal(state.membership.installationId,home);assert(state.incidents.some(incident=>incident.id===remoteId));assert(state.incidents.some(incident=>incident.id===otherId));
 assert.equal(state.incidents.find(incident=>incident.id===localId).attackMetadata.source,'log');
 assert.deepEqual(state.incidents.find(incident=>incident.id===localId).attackMetadata.targets[0].cves,[currentCve]);
 const savedMulti=state.incidents.find(incident=>incident.id===multiId).attackMetadata;
 assert.deepEqual(savedMulti.targets.find(target=>target.siteId===home).cves,[currentCve]);assert.deepEqual(savedMulti.targets.find(target=>target.siteId===remote).cves,['CVE-2021-44228']);
 assert.equal(state.incidents.find(incident=>incident.id===legacyId).attackMetadata.source,'report-text');
 assert.equal(state.exposure.homeSiteId,home);assert(state.exposure.comparisons.some(comparison=>comparison.reportId===remoteId&&comparison.level==='high'));
 const apiSimilarity=state.exposure.comparisons.find(comparison=>comparison.reportId===remoteId).similarity;
 assert.equal(apiSimilarity.percent,90);assert.equal(apiSimilarity.coverage,90);assert.equal(apiSimilarity.localReportId,localId);assert.equal(row(apiSimilarity,'behaviors').points,25,'The API passes scoped raw observations into current-behavior comparison');assert.equal(Object.hasOwn(state.exposure,'probability'),false);
 assert.equal(state.exposure.comparisons.find(comparison=>comparison.reportId===otherId).similarity.percent,apiSimilarity.percent,'Different CVEs do not alter otherwise matching current threat patterns');
 assert.equal((await call('/api/commander/overview')).status,403);
 assert.equal((await call('/api/commander/login','POST',{password:env.COMMANDER_PASSWORD,homeSiteId:remote})).status,400);
 const commandLogin=await call('/api/commander/login','POST',{password:env.COMMANDER_PASSWORD});assert.equal(commandLogin.status,200);const both=cookie+'; '+commandLogin.headers.get('set-cookie').split(';')[0];
 const commandSession=await(await call('/api/commander/session','GET',undefined,both)).json();assert.equal(commandSession.membership.installationId,home);
 const command=await(await call('/api/commander/overview','GET',undefined,both)).json();assert.equal(command.counts.totalInstallations,1);assert.equal(command.counts.active,3);assert(command.reports.every(incident=>incident.installations.every(site=>site.id===home)));
 assert(!command.reports.some(incident=>incident.id===remoteId||incident.id===otherId));assert(!JSON.stringify(command).includes('203.0.113.74'));
 assert.equal(command.exposure.comparisons.find(comparison=>comparison.reportId===remoteId).similarity.percent,apiSimilarity.percent);assert.equal(Object.hasOwn(command.exposure,'probability'),false);
 const document={kind:'aar',title:'Local review',body:'Isolated fixture review.',status:'draft',incidentId:localId};
 assert.equal((await call('/api/commander/documents','POST',{...document,incidentId:remoteId},both)).status,400);
 assert.equal((await call('/api/commander/documents','POST',document,both)).status,201);
 const externalDocumentId=crypto.randomUUID();db.prepare('INSERT INTO commander_documents (id,kind,incident_id,title,body,status,revision,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)').run(externalDocumentId,'aar',remoteId,'Legacy external review','Preserved but outside current scope.','draft',1,current,current);
 const scopedCommand=await(await call('/api/commander/overview','GET',undefined,both)).json();assert(!scopedCommand.documents.some(item=>item.id===externalDocumentId));assert(scopedCommand.documents.some(item=>item.title===document.title));
 assert.equal((await call('/api/commander/documents/'+externalDocumentId,'PATCH',{...document,revision:1},both)).status,403,'A legacy external document cannot be reassigned into the current base');
 const finalSession=await(await call('/api/session')).json();assert.equal(finalSession.membership.installationId,home);
 console.log('PASS — server-owned Patrick affiliation, commander scope, target-specific metadata parsing, current unresolved threat-pattern similarity independent of CVEs/products, per-report fresh behavioral evidence, independent service tokens, provenance separation, single-report matching, self-exclusion, bounded deterministic results, and API/commander privacy.');
}finally{rmSync(directory,{recursive:true,force:true});}
