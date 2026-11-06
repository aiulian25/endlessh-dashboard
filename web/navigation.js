/* The attacker URL is an investigation snapshot, restored by browser Back. */
const sorts = new Set(['trapped_seconds','connections','last_seen','last_activity','first_seen','ip','country']);
const statuses = new Set(['','trapped','gave_up','unknown']);
export function attackerState(query = new URLSearchParams()) {
  const page = Number(query.get('page'));
  return {
    q: query.get('q') || '', country: query.get('country_key') || '',
    status: statuses.has(query.get('status')) ? query.get('status') : '',
    basis: query.get('basis') === 'observed' ? 'observed' : 'activity',
    sort: sorts.has(query.get('sort')) ? query.get('sort') : 'trapped_seconds',
    order: query.get('order') === 'asc' ? 'asc' : 'desc',
    page: Number.isSafeInteger(page) && page > 0 ? page : 1, total: 0,
  };
}
export function attackerHash(state = {}, machines = '0', windowValue = '24h') {
  const query = new URLSearchParams({machines,window:windowValue});
  for (const [key,value] of Object.entries({q:state.q,country_key:state.country,status:state.status,basis:state.basis,sort:state.sort,order:state.order,page:state.page})) {
    if (value !== undefined && value !== '') query.set(key,String(value));
  }
  return '#/attackers?' + query;
}
export function rememberAttackers(state, machines, windowValue) {
  if (typeof history !== 'undefined' && typeof location !== 'undefined') {
    history.replaceState(history.state,'',attackerHash(state,machines,windowValue));
  }
}
