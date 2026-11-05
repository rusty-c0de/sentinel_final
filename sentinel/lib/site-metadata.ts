import type {Metadata} from 'next';

// Public branding only. Link-preview crawlers do not receive workspace records.
const siteOrigin='https://sentinel-incident-globe.ovalllama.chatgpt.site';
const logoUrl=new URL('/branding/space-force.jpg',siteOrigin).href;
const logoAlt='United States Space Force seal';

export function pageMetadata(path:string,title:string,description:string):Metadata {
 return {
  metadataBase:new URL(siteOrigin),
  title,
  description,
  openGraph:{
   type:'website',
   siteName:'Sentinel',
   title,
   description,
   url:new URL(path,siteOrigin).href,
   images:[{url:logoUrl,width:452,height:442,type:'image/jpeg',alt:logoAlt}],
  },
  twitter:{card:'summary',title,description,images:[{url:logoUrl,alt:logoAlt}]},
  icons:{icon:{url:logoUrl,type:'image/jpeg'},apple:{url:logoUrl,type:'image/jpeg'}},
 };
}
