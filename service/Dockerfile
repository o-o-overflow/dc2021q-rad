from dc2021q-rad-base
from rust:alpine
workdir /
copy --from=0 /src/target/*/rad_exec /src/target/*/rad_fw /
copy data/de438s.exb data/de438s.fxb /data/
run echo 'OOO{tho.gh_t.is.be_m.dness_ye..t.er...s_m.th.d..n.it?}' >/FLAG \
    && cp /FLAG /flag \
    && chmod 440 /FLAG /flag
entrypoint ["/rad_exec"]
