import {installationById} from './installations';

// One server-owned affiliation shared by the operator and commander roles.
// The existing shared-password workspace does not identify individual people.
export const HOME_INSTALLATION_ID='patrick-space-force-base';
const installation=installationById(HOME_INSTALLATION_ID)!;
export const HOME_MEMBERSHIP=Object.freeze({installationId:installation.id,installationName:installation.name});
