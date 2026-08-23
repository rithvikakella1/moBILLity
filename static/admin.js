/* Admin analytics dashboard.
 *
 * Moved out of admin.html so the Content-Security-Policy can set
 * script-src 'self' with no 'unsafe-inline'. The page is server-gated:
 * FastAPI checks administrator access before returning the HTML, and the
 * /api/admin/analytics endpoint enforces it again independently.
 */
const fmt = value => value ? new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(value)) : '—';
    const esc = value => String(value ?? '').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    async function load(){
      const response=await fetch('/api/admin/analytics');
      if(response.status===401){location.href='/login';return}
      if(!response.ok)throw new Error(response.status===403?'This account is not an administrator.':'Analytics could not be loaded.');
      const data=await response.json(), t=data.totals;
      document.querySelector('#notice').textContent=`Events are retained for ${data.retention_days} days. Clinical text, codes, IP addresses, location, and device fingerprints are never collected by this analytics system.`;
      document.querySelector('#stats').innerHTML=[
        ['Registered users',t.registered_users],['Verified users',t.verified_users],
        ['Active users',t.active_users],['Tracked actions',t.total_events]
      ].map(([l,n])=>`<div class="card"><div class="label">${l}</div><div class="number">${n}</div></div>`).join('');
      const max=Math.max(1,...data.daily.map(d=>d.events));
      document.querySelector('#chart').innerHTML=data.daily.map(d=>`<div class="bar" style="height:${Math.max(2,d.events/max*100)}%"><span>${esc(d.day)} · ${d.events} actions · ${d.registrations} registrations</span></div>`).join('');
      document.querySelector('#events').innerHTML=data.top_events.length?data.top_events.map(e=>`<div class="event"><span>${esc(e.event_name.replaceAll('_',' '))}<small>${esc(e.page)}</small></span><b>${e.count}</b></div>`).join(''):'<div class="empty">No activity yet.</div>';
      document.querySelector('#users').innerHTML=data.users.map(u=>`<tr><td class="name">${esc(u.full_name||'Unnamed user')}<small>${esc(u.email)}</small></td><td>${fmt(u.created_at)}</td><td><span class="pill ${u.analytics_enabled?'':'off'}">${u.analytics_enabled?'Analytics on':'Opted out'}</span></td><td>${u.event_count}</td><td>${u.analyses||0}</td><td>${fmt(u.last_active_at)}</td></tr>`).join('');
    }
    load().catch(error=>document.querySelector('main').innerHTML=`<div class="card error">${esc(error.message)}</div>`);
