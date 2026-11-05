import Sentinel from '../components/Sentinel';
import {pageMetadata} from '../../lib/site-metadata';
export const metadata=pageMetadata('/commander','Commander Overview | Sentinel','A protected command briefing with reported cyber activity, decision support, and after-action reviews.');
export default function CommanderPage(){return <Sentinel initialView="commander"/>;}
