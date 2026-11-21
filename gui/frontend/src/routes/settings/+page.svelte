<script lang="ts">
  import type { Settings } from "$lib/api/types";
  import Icon from "$lib/components/Icon.svelte";
  import Toggle from "$lib/components/Toggle.svelte";
  import { settings } from "$lib/data/mock";
  import { toast } from "$lib/state/toast.svelte";

  // Local working copy: the real client PATCHes each change once the daemon
  // endpoints land. Keeping one object means every control is bound the same way.
  let form = $state<Settings>({ ...settings });

  function save<K extends keyof Settings>(key: K) {
    void key;
  }

  function changed<K extends keyof Settings>(key: K) {
    save(key);
    toast.show("Saved");
  }
</script>

<div class="panel-page">
  <div class="panel-tools">
    <span class="summary">Changes apply immediately.</span>
    <div class="right">
      <button class="btn small ghost" onclick={() => toast.show("Opening the help guide")}>Get help</button>
      <button class="btn small" onclick={() => toast.show("Checking for updates")}>
        <Icon name="refresh" cls="sm" /> Check for updates
      </button>
    </div>
  </div>

  <div class="settings-grid">
    <article class="card">
      <div class="card-head"><h3>Connection</h3></div>
      <div class="setting">
        <div class="copy"><strong>Connect automatically</strong><span>Start egress when you sign in.</span></div>
        <div class="control">
          <Toggle bind:checked={form.connect_automatically} label="Connect automatically" onchange={() => changed("connect_automatically")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Smart routing</strong><span>Direct when possible, relay when needed.</span></div>
        <div class="control">
          <Toggle bind:checked={form.smart_routing} label="Smart routing" onchange={() => changed("smart_routing")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Allow relay fallback</strong><span>Use a trusted relay if a direct path fails.</span></div>
        <div class="control">
          <Toggle bind:checked={form.relay_fallback} label="Allow relay fallback" onchange={() => changed("relay_fallback")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Relay region</strong><span>Choose the closest cloud relay.</span></div>
        <div class="control">
          <select class="select" bind:value={form.relay_region} onchange={() => changed("relay_region")}>
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
          <Toggle bind:checked={form.share_connection} label="Share my connection" onchange={() => changed("share_connection")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Who can use it</strong><span>People in your circle only.</span></div>
        <div class="control">
          <select class="select" bind:value={form.share_scope} disabled={!form.share_connection} onchange={() => changed("share_scope")}>
            <option value="friends">Friends only</option>
            <option value="close">Close friends</option>
            <option value="none">Nobody</option>
          </select>
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Monthly limit</strong><span>Stop sharing after this much data.</span></div>
        <div class="control">
          <input
            class="input"
            type="number"
            min="1"
            bind:value={form.share_limit_gb}
            disabled={!form.share_connection}
            aria-label="Monthly sharing limit in gigabytes"
            onchange={() => changed("share_limit_gb")}
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
          <Toggle bind:checked={form.hide_public_address} label="Hide my public address" onchange={() => changed("hide_public_address")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Relay only</strong><span>Never try a direct connection.</span></div>
        <div class="control">
          <Toggle bind:checked={form.relay_only} label="Relay only" onchange={() => changed("relay_only")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Share blocked-site reports</strong><span>Help your circle learn which sites are blocked.</span></div>
        <div class="control">
          <Toggle bind:checked={form.share_reports} label="Share blocked-site reports" onchange={() => changed("share_reports")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Clear my activity</strong><span>Remove the local history on this device.</span></div>
        <div class="control">
          <button class="btn small ghost" onclick={() => toast.show("Local activity cleared")}>Clear</button>
        </div>
      </div>
    </article>

    <article class="card">
      <div class="card-head"><h3>Notifications and appearance</h3></div>
      <div class="setting">
        <div class="copy"><strong>Friend comes online</strong><span>Know when someone in your circle is around.</span></div>
        <div class="control">
          <Toggle bind:checked={form.notify_friend} label="Notify when a friend comes online" onchange={() => changed("notify_friend")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Site unblocked</strong><span>A quiet note when egress fixes a site.</span></div>
        <div class="control">
          <Toggle bind:checked={form.notify_site} label="Notify when a site is unblocked" onchange={() => changed("notify_site")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Connection drops</strong><span>Tell me if protection stops.</span></div>
        <div class="control">
          <Toggle bind:checked={form.notify_drop} label="Notify when the connection drops" onchange={() => changed("notify_drop")} />
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Accent</strong><span>Follows your wallpaper through bread-theme.</span></div>
        <div class="control">
          <div class="swatches" aria-hidden="true">
            <i style="background:#eab672"></i><i style="background:#e3a85c"></i><i style="background:#f6c477"></i><i style="background:#8fc3bd"></i>
          </div>
        </div>
      </div>
      <div class="setting">
        <div class="copy"><strong>Text size</strong><span>Comfortable · Varela Round 14 px</span></div>
        <div class="control">
          <select class="select" bind:value={form.text_size} onchange={() => changed("text_size")}>
            <option value="comfortable">Comfortable</option>
            <option value="compact">Compact</option>
            <option value="large">Large</option>
          </select>
        </div>
      </div>
    </article>
  </div>
</div>
