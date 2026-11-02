"""Closed-gate finite observation schema; no raw SDK or user content."""
import copy

MAX_EVENTS = 32
MAX_OMITTED = 1024
CLASSES = ('lifecycle', 'sdk', 'tools', 'hooks', 'permissions', 'subagents', 'usage', 'errors')
TERMINAL = ('COMPLETED', 'FAILED', 'CANCELLED', 'INTERRUPTED', 'CLOSED')
STAGES = ('first', 'second')

def enabled():
    # No configuration switch: changing this requires separate security/access qualification.
    return False

def empty():
    return {'schema_version': 1, 'events': [],
            'availability': {name: 'unknown' for name in CLASSES},
            'state': {'stages': [], 'terminal': None},
            'truncation': {'state': 'not_truncated', 'omitted_count': 0,
                           'basis': 'local_projection_only', 'upstream_completeness': 'unknown'}}

def validate(value):
    if not isinstance(value, dict) or set(value) != {'schema_version','events','availability','truncation','state'}:
        raise ValueError('INVALID_FINITE_PROJECTION')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('INVALID_FINITE_PROJECTION')
    if value['availability'] != {name: 'unknown' for name in CLASSES}:
        raise ValueError('INVALID_FINITE_PROJECTION')
    events=value['events']
    if not isinstance(events,list) or len(events)>MAX_EVENTS: raise ValueError('INVALID_FINITE_PROJECTION')
    seen=set(); terminal=False
    for n,e in enumerate(events,1):
        if not isinstance(e,dict) or set(e)!={'seq','kind','value','provenance'} or type(e['seq']) is not int or e['seq']!=n:
            raise ValueError('INVALID_FINITE_PROJECTION')
        if terminal: raise ValueError('INVALID_FINITE_PROJECTION')
        if e['kind']=='stage_completed':
            if e['value'] not in STAGES or e['value'] in seen or e['provenance']!='host_controller_observation': raise ValueError('INVALID_FINITE_PROJECTION')
            if e['value']=='second' and 'first' not in seen: raise ValueError('INVALID_FINITE_PROJECTION')
            seen.add(e['value'])
        elif e['kind']=='terminal':
            if e['value'] not in TERMINAL or e['provenance']!='host_owner_observation': raise ValueError('INVALID_FINITE_PROJECTION')
            terminal=True
        elif e['kind']=='status_observed':
            if e['value'] not in ('STARTING','LOGIN_REQUIRED','RUNNING','CANCEL_REQUESTED','ENDING') or e['provenance']!='host_owner_observation': raise ValueError('INVALID_FINITE_PROJECTION')
        else: raise ValueError('INVALID_FINITE_PROJECTION')
    state=value['state']
    if (not isinstance(state,dict) or set(state)!={'stages','terminal'} or
            state['stages'] not in ([], ['first'], ['first','second']) or
            state['terminal'] not in (*TERMINAL,None) or
            not seen.issubset(set(state['stages'])) or
            (terminal and state['terminal'] != events[-1]['value'])):
        raise ValueError('INVALID_FINITE_PROJECTION')
    t=value['truncation']
    if not isinstance(t,dict) or set(t)!={'state','omitted_count','basis','upstream_completeness'}: raise ValueError('INVALID_FINITE_PROJECTION')
    n=t['omitted_count']
    if (type(n) is not int or not 0<=n<=MAX_OMITTED or t['basis']!='local_projection_only'
            or t['upstream_completeness']!='unknown' or t['state'] not in ('not_truncated','truncated')
            or (t['state']=='not_truncated' and n!=0)
            or (t['state']=='truncated' and (n==0 or len(events)!=MAX_EVENTS))):
        raise ValueError('INVALID_FINITE_PROJECTION')
    missing = len(set(state['stages']) - seen) + int(state['terminal'] is not None and not terminal)
    if missing > n or (terminal and n):
        raise ValueError('INVALID_FINITE_PROJECTION')
    if t['state']=='not_truncated' and (set(state['stages']) != seen or (state['terminal'] is not None) != terminal):
        raise ValueError('INVALID_FINITE_PROJECTION')
    return value

def append(value, kind, item):
    result=copy.deepcopy(validate(value))
    if result['state']['terminal'] is not None: raise ValueError('FINITE_PROJECTION_TERMINAL')
    if kind=='stage_completed':
        if item not in STAGES or item in result['state']['stages'] or (item=='second' and result['state']['stages'] != ['first']):
            raise ValueError('INVALID_FINITE_STAGE')
        result['state']['stages'].append(item)
        provenance='host_controller_observation'
    elif kind=='terminal':
        if item not in TERMINAL: raise ValueError('INVALID_FINITE_TERMINAL')
        result['state']['terminal']=item
        provenance='host_owner_observation'
    elif kind=='status_observed':
        if item not in ('STARTING','LOGIN_REQUIRED','RUNNING','CANCEL_REQUESTED','ENDING'): raise ValueError('INVALID_FINITE_STATUS')
        provenance='host_owner_observation'
    else: raise ValueError('INVALID_FINITE_EVENT')
    if len(result['events']) >= MAX_EVENTS:
        t=result['truncation']
        if t['omitted_count'] >= MAX_OMITTED: raise ValueError('FINITE_PROJECTION_LIMIT')
        t['state']='truncated'; t['omitted_count']+=1
    else:
        result['events'].append({'seq':len(result['events'])+1,'kind':kind,'value':item,'provenance':provenance})
    return validate(result)
