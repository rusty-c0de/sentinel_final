import type { Metadata,Viewport } from 'next';
import {pageMetadata} from '../lib/site-metadata';
import './globals.css';
export const metadata:Metadata={...pageMetadata('/','Sentinel | Defensive Cyber Harness','Analyze log evidence, identify defensive cyber patterns, and trace observed sources to target installations.'),robots:{index:false,follow:false}};
export const viewport:Viewport={width:'device-width',initialScale:1,viewportFit:'cover',interactiveWidget:'resizes-content',themeColor:'#10181c',colorScheme:'dark'};
export default function RootLayout({children}:{children:React.ReactNode}){return <html lang="en"><body>{children}</body></html>;}
