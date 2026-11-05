import Sentinel from '../components/Sentinel';
import {pageMetadata} from '../../lib/site-metadata';
export const metadata=pageMetadata('/threat-intel','Live Threat Intel | Sentinel','CISA, SANS ISC, and NIST NVD intelligence, checked every five minutes in your protected Sentinel workspace.');
export default function ThreatIntelPage(){return <Sentinel initialView="intel"/>;}
