-- The protection triggers fire in every session_replication_role. A trigger enabled only for origin sessions is
-- switched off by SET session_replication_role = replica, which any role granted SET on that parameter (or holding it
-- as a role default) could use to update or delete append-only rows. ENABLE ALWAYS closes that, and Open requires it.
ALTER TABLE audit_chain_heads ENABLE ALWAYS TRIGGER audit_chain_heads_advance;
ALTER TABLE audit_chain_heads ENABLE ALWAYS TRIGGER audit_chain_heads_no_delete;
ALTER TABLE audit_chain_heads ENABLE ALWAYS TRIGGER audit_chain_heads_no_truncate;
ALTER TABLE audit_entries ENABLE ALWAYS TRIGGER audit_entries_append_only_row;
ALTER TABLE audit_entries ENABLE ALWAYS TRIGGER audit_entries_append_only_stmt;
ALTER TABLE consumed_decisions ENABLE ALWAYS TRIGGER consumed_decisions_append_only_row;
ALTER TABLE consumed_decisions ENABLE ALWAYS TRIGGER consumed_decisions_append_only_stmt;
ALTER TABLE deliveries ENABLE ALWAYS TRIGGER deliveries_append_only_row;
ALTER TABLE deliveries ENABLE ALWAYS TRIGGER deliveries_append_only_stmt;
