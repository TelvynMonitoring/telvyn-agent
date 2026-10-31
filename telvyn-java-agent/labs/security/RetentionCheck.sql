-- Point diagnostic on real laboratory records. No INSERT, UPDATE or DELETE.
-- psql -v tenant=<authorized tenant> -v ON_ERROR_STOP=1 -f RetentionCheck.sql
BEGIN READ ONLY;
SET LOCAL ROLE telvyn_app;
SELECT set_config('app.tenant_id', :'tenant', true);
DO $$
DECLARE sample public.noc_apm_attack_lab_event; before_cutoff integer; after_cutoff integer;
BEGIN
 SELECT * INTO sample FROM public.noc_apm_attack_lab_event
 WHERE tenant=current_setting('app.tenant_id') ORDER BY observed_at LIMIT 1;
 IF sample.id IS NULL THEN RAISE EXCEPTION 'A real laboratory event is required'; END IF;
 -- Same strict timestamp boundary as the cleanup: equality is preserved.
 SELECT count(*) INTO before_cutoff FROM public.noc_apm_attack_lab_event
 WHERE tenant=current_setting('app.tenant_id') AND id=sample.id AND observed_at<sample.observed_at;
 SELECT count(*) INTO after_cutoff FROM public.noc_apm_attack_lab_event
 WHERE tenant=current_setting('app.tenant_id') AND id=sample.id AND observed_at<sample.observed_at+interval '1 microsecond';
 IF before_cutoff<>0 OR after_cutoff<>1 THEN RAISE EXCEPTION 'Invalid retention boundary'; END IF;
 IF EXISTS(SELECT 1 FROM public.noc_apm_attack_lab_event WHERE tenant<>current_setting('app.tenant_id'))
 THEN RAISE EXCEPTION 'Unexpected tenant visibility'; END IF;
END $$;
ROLLBACK;
