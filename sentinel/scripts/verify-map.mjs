import {strict as assert} from 'node:assert';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
const code=ts.transpileModule(readFileSync('lib/map-texture.ts','utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText;
const {paintMapTexture}=await import('data:text/javascript;base64,'+Buffer.from(code).toString('base64'));
const polygons=JSON.parse(readFileSync('public/world.json','utf8')),fills=[];let rings=[];
const ctx={clearRect(){},beginPath(){rings=[];},moveTo(x,y){rings.push([[x,y]]);},lineTo(x,y){rings.at(-1).push([x,y]);},closePath(){},fill(){fills.push(rings);}};
paintMapTexture(ctx,polygons,360,180);
function inside(r,x,y){let yes=false;for(let i=0,j=r.length-1;i<r.length;j=i++){const a=r[i],b=r[j];if((a[1]>y)!==(b[1]>y)&&x<(b[0]-a[0])*(y-a[1])/(b[1]-a[1])+a[0])yes=!yes;}return yes;}
function land(lon,lat){return fills.some(poly=>poly.reduce((s,r)=>s!==inside(r,lon+180,90-lat),false));}
assert.equal(land(0,69),false,'Norwegian Sea must not become an Arctic land stripe');assert.equal(land(-10,69),false,'North Atlantic must remain ocean');assert.equal(land(100,70),true,'Arctic Russian coastline remains present');
for(let lon=-175;lon<180;lon+=10){assert.equal(land(lon,89),false,'North Pole remains ocean');assert.equal(land(lon,-89),true,'Antarctica closes around the South Pole');}
const russia=JSON.parse(readFileSync('lib/countries.json','utf8')).find(country=>country.id==='643');
assert(russia.lat>50&&russia.lat<70&&russia.lng>80&&russia.lng<120,'Russia country marker belongs on the mainland, not near Alaska');
assert.equal(land(russia.lng,russia.lat),true,'Russia country marker must sit on the packaged land geometry');
console.log('PASS: dateline wrapping, Arctic ocean, Russian coastline and both polar closures.');
