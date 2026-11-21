class ToastState {
  message = $state("");
  visible = $state(false);
  private timer: ReturnType<typeof setTimeout> | null = null;

  show(message: string) {
    this.message = message;
    this.visible = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.visible = false;
    }, 2800);
  }
}

export const toast = new ToastState();
