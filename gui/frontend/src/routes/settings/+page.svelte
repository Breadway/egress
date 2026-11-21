<script lang="ts">
  import type { Settings } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import Toggle from "$lib/components/Toggle.svelte";
  import { app } from "$lib/state/app.svelte";
  import { toast } from "$lib/state/toast.svelte";

  async function save<K extends keyof Settings>(key: K) {
    try {
      await app.patch({ [key]: app.settings[key] } as Partial<Settings>);
      toast.show("Saved");
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not save that setting");
    }
  }

  async function clearActivity() {
    try {
      await app.clearActivity();
      toast.show("Local activity cleared");
    } catch (err) {
      toast.show(err instanceof Error ? err.message : "Could not clear the activity");
    }
  }
</script>

<div class="panel-page">
  <div class="panel-tools">
    <span class="summary">Changes save as you go.</span>
  </div>

  <div class="settings-grid">
    <article class="card">
      <div class="card-head"><h3>Connection</h3></div>
      <div class="setting">
        <div class="copy"><strong>Connect automatically</strong><span>Start egress when you sign in.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.connect_automatically} label="Connect automatically" onchange={() => save("connect_automatically")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Allow relay fallback</strong><span>Use a trusted relay if a direct path fails.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.relay_fallback} label="Allow relay fallback" onchange={() => save("relay_fallback")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Relay region</strong><span>Choose the closest cloud relay. Applies on the next start.</span></div>
        <div class="control">
          <select class="select" bind:value={app.settings.relay_region} onchange={() => save("relay_region")}>
            <option value="automatic">Automatic</option>
            <option value="sydney">Sydney</option>
            <option value="singapore">Singapore</option>
            <option value="los_angeles">Los Angeles</option>
          </select>
        </div>
      </div>
    </article>

    <article class="card">
      <div class="card-head"><h3>Sharing</h3></div>
      <div class="setting">
        <div class="copy"><strong>Share my connection</strong><span>Let friends in your circle use your internet.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.share_connection} label="Share my connection" onchange={() => save("share_connection")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Who can use it</strong><span>People in your circle only.</span></div>
        <div class="control">
          <select class="select" bind:value={app.settings.share_scope} disabled={!app.settings.share_connection} onchange={() => save("share_scope")}>
            <option value="friends">Friends only</option>
            <option value="none">Nobody</option>
          </select>
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Monthly limit</strong><span>Stop sharing after this much data each month.</span></div>
        <div class="control">
          <input
            class="input"
            type="number"
            min="1"
            bind:value={app.settings.share_limit_gb}
            disabled={!app.settings.share_connection}
            aria-label="Monthly sharing limit in gigabytes"
            onchange={() => save("share_limit_gb")}
          />
          <span class="unit">GB</span>
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Sharing uses your data</strong><span>Friends' traffic counts toward your home plan.</span></div>
        <div class="control"><Icon name="alert" cls="sm faint" /></div>
      </div>
    </article>

    <article class="card">
      <div class="card-head"><h3>Privacy</h3></div>
      <div class="setting">
        <div class="copy"><strong>Hide my public address</strong><span>Friends only see a relayed connection.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.hide_public_address} label="Hide my public address" onchange={() => save("hide_public_address")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Relay only</strong><span>Never try a direct connection.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.relay_only} label="Relay only" onchange={() => save("relay_only")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Share blocked-site reports</strong><span>Help your circle learn which sites are blocked.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.share_reports} label="Share blocked-site reports" onchange={() => save("share_reports")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Clear my activity</strong><span>Remove the local history on this device.</span></div>
        <div class="control">
          <button class="btn small ghost" onclick={clearActivity}>Clear</button>
        </div>
      </div>
    </article>

    <article class="card">
      <div class="card-head"><h3>Notifications and appearance</h3></div>
      <div class="setting">
        <div class="copy"><strong>Friend comes online</strong><span>Know when someone in your circle is around.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.notify_friend} label="Notify when a friend comes online" onchange={() => save("notify_friend")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Site unblocked</strong><span>A quiet note when egress fixes a site.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.notify_site} label="Notify when a site is unblocked" onchange={() => save("notify_site")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Connection drops</strong><span>Tell me if protection stops.</span></div>
        <div class="control">
          <Toggle bind:checked={app.settings.notify_drop} label="Notify when the connection drops" onchange={() => save("notify_drop")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Text size</strong><span>Changes text across the app.</span></div>
        <div class="control">
          <select class="select" bind:value={app.settings.text_size} onchange={() => save("text_size")}>
            <option value="comfortable">Comfortable</option>
            <option value="compact">Compact</option>
            <option value="large">Large</option>
          </select>
        </div>
      </div>
    </article>
  </div>
</div>
