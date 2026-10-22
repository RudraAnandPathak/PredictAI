from __future__ import annotations
REGULAR_DOCUMENT_LIMIT = 2
REGULAR_PAGES_PER_DOCUMENT = 30
REGULAR_MAX_FILE_MB = 10
REGULAR_DAILY_AI_LIMIT = 3

def require_owner(user: dict | None) -> None:
    if not user or user.get('role') != 'owner':
        raise PermissionError('The Owner Command Center is available only to the authenticated owner.')

def get_analytics():
    from predictai_core.phase8.accounts import _connect
    with _connect() as conn:
        users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        special = conn.execute("SELECT COUNT(*) FROM users WHERE special_access=1 AND role!='owner'").fetchone()[0]
        events = {r['event_type']: r['n'] for r in conn.execute('SELECT event_type, COUNT(*) AS n FROM usage_events GROUP BY event_type')}
        daily = [dict(r) for r in conn.execute(
            "SELECT date(created_at) AS day, event_type, COUNT(*) AS count FROM usage_events GROUP BY date(created_at), event_type ORDER BY day DESC LIMIT 100")]
        return {'registered_users': users, 'special_users': special,
                'documents_uploaded': events.get('document_upload',0), 'questions_asked': events.get('question_asked',0),
                'reports_generated': events.get('report_generated',0), 'ai_requests_succeeded': events.get('ai_success',0),
                'ai_requests_failed': events.get('ai_error',0), 'daily_usage': daily, 'tracked_events': events}

def render_owner_dashboard(user: dict):
    import os
    import pandas as pd
    import streamlit as st
    from predictai_core.phase8.accounts import list_users, set_special_access, set_blocked, record_event
    require_owner(user)
    st.title('👑 PredictAI Owner Command Center')
    st.caption('Private administrative analytics. Counts reflect events recorded by this application.')
    data = get_analytics()
    cols = st.columns(4)
    for col, label, key in [(cols[0],'Registered users','registered_users'),(cols[1],'Special users','special_users'),
                            (cols[2],'Documents uploaded','documents_uploaded'),(cols[3],'Questions asked','questions_asked')]:
        col.metric(label, data[key])
    cols2 = st.columns(3)
    cols2[0].metric('Reports generated', data['reports_generated'])
    cols2[1].metric('AI requests completed', data['ai_requests_succeeded'])
    cols2[2].metric('AI requests failed', data['ai_requests_failed'])
    st.info('Usage metrics are based on instrumented events. Older or uninstrumented actions are not included.')
    st.subheader('👥 User Management & Special Access')
    users = list_users()
    if users:
        st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)
        eligible = [u['username'] for u in users if u['role'] != 'owner']
        st.caption('New accounts require a full legal name and email address. Existing accounts remain intact; their new profile fields may be blank until collected separately.')
        if eligible:
            selected = st.selectbox('Select user account', eligible)
            selected_user = next(u for u in users if u['username'] == selected)
            st.write(f"**Legal name:** {selected_user.get('full_legal_name') or 'Not collected (legacy account)'}  \\n**Email:** {selected_user.get('email') or 'Not collected (legacy account)'}  \\n**Status:** {'BLOCKED' if selected_user.get('is_blocked') else 'Active'}")
            st.markdown('#### Account access')
            access_cols = st.columns(2)
            if selected_user.get('is_blocked'):
                if access_cols[0].button('Unblock account', type='primary', use_container_width=True):
                    try:
                        set_blocked(user, selected, False)
                        st.success(f'Unblocked {selected}.')
                        st.rerun()
                    except Exception as exc: st.error(str(exc))
            else:
                if access_cols[0].button('Block account', type='primary', use_container_width=True):
                    try:
                        set_blocked(user, selected, True)
                        st.success(f'Blocked {selected}. Their next request will be denied and their session invalidated on rerun.')
                        st.rerun()
                    except Exception as exc: st.error(str(exc))
            action = st.radio('Special access', ['Grant','Revoke'], horizontal=True,
                              index=0 if selected_user['special_access'] else 1)
            if access_cols[1].button('Apply special access', use_container_width=True):
                try:
                    set_special_access(user, selected, action == 'Grant')
                    record_event(user['username'], 'admin_action', f'{action.lower()} special access for {selected}')
                    st.success(f'Special access {action.lower()}ed for {selected}.')
                    st.rerun()
                except Exception as exc: st.error(str(exc))
    else: st.info('No registered users yet.')
    st.subheader('📈 Daily usage history')
    if data['daily_usage']: st.dataframe(pd.DataFrame(data['daily_usage']), use_container_width=True, hide_index=True)
    else: st.info('No usage events have been recorded yet.')
    st.subheader('⚙️ Platform configuration status')
    st.write({'Cloudflare AI configured': bool(os.getenv('CLOUDFLARE_ACCOUNT_ID') and os.getenv('CLOUDFLARE_API_TOKEN')),
              'Special-access code configured': bool(os.getenv('PREDICTAI_SPECIAL_ACCESS_CODE')),
              'Owner identity configured': bool(os.getenv('PREDICTAI_OWNER_USERNAME') and os.getenv('PREDICTAI_OWNER_SETUP_SECRET')),
              'Regular-user document limit': REGULAR_DOCUMENT_LIMIT,
              'Pages per regular-user document': REGULAR_PAGES_PER_DOCUMENT,
              'Max regular-user file size (MB)': REGULAR_MAX_FILE_MB,
              'Daily AI tasks for regular users': REGULAR_DAILY_AI_LIMIT})
