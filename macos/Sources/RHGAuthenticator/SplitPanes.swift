import AppKit
import SwiftUI

/// Two panes side by side with a draggable divider, in place of `HSplitView`,
/// whose divider shows no resize cursor (`pointerStyle(.columnResize)` needs
/// macOS 15). Half and half until the first drag; after it the leading pane
/// keeps its width and the trailing pane takes any window resize.
@MainActor
struct SplitPanes<Leading: View, Trailing: View>: View {
    let leadingMinWidth: CGFloat
    let trailingMinWidth: CGFloat
    let leading: Leading
    let trailing: Trailing

    /// The leading pane's width as last dragged, nil until the first drag.
    /// The clamp never rewrites it, so a width a narrow window squeezed
    /// comes back when the window widens.
    @State private var leadingWidth: CGFloat?
    /// The shown width when the drag began; resets itself when it ends.
    @GestureState private var dragStart: CGFloat?
    @Environment(\.isEnabled) private var isEnabled

    /// The divider's own width.
    private static var dividerWidth: CGFloat { 1 }
    /// The divider plus 6 pt of the trailing pane, clear of the leading
    /// pane's scroller at its trailing edge.
    private static var handleWidth: CGFloat { 7 }

    init(
        leadingMinWidth: CGFloat, trailingMinWidth: CGFloat,
        @ViewBuilder leading: () -> Leading, @ViewBuilder trailing: () -> Trailing
    ) {
        self.leadingMinWidth = leadingMinWidth
        self.trailingMinWidth = trailingMinWidth
        self.leading = leading()
        self.trailing = trailing()
    }

    var body: some View {
        GeometryReader { proxy in
            let available = proxy.size.width
            let shown = clamped(leadingWidth ?? (available - Self.dividerWidth) / 2, available: available)
            HStack(spacing: 0) {
                leading
                    .frame(width: shown)
                Divider()
                trailing
                    .frame(maxWidth: .infinity)
            }
            .overlay(alignment: .leading) {
                handle(shown: shown, available: available)
                    .offset(x: shown)
            }
        }
    }

    /// A clear strip over the divider that drags it and shows the ↔ cursor.
    private func handle(shown: CGFloat, available: CGFloat) -> some View {
        Color.clear
            .frame(width: Self.handleWidth)
            .contentShape(Rectangle())
            .onContinuousHover { phase in
                if case .active = phase {
                    // On every move, so a view underneath can't keep it reset.
                    if isEnabled { NSCursor.resizeLeftRight.set() }
                } else if dragStart == nil {
                    NSCursor.arrow.set()
                }
            }
            .gesture(
                // Global: a frame that doesn't move with the strip.
                DragGesture(minimumDistance: 0, coordinateSpace: .global)
                    .updating($dragStart) { _, start, _ in
                        if start == nil { start = shown }
                    }
                    .onChanged { value in
                        // Hover updates may not arrive while the button is
                        // down, and a text field underneath would set the
                        // I-beam. On the first event dragStart may still be
                        // nil, but the translation is then 0.
                        NSCursor.resizeLeftRight.set()
                        leadingWidth = clamped((dragStart ?? shown) + value.translation.width, available: available)
                    }
                    .onEnded { _ in
                        // The next move over the strip sets ↔ again.
                        NSCursor.arrow.set()
                    }
            )
            // A hidden tab is disabled, not removed (RootView.tabVisible).
            .onChange(of: isEnabled) { _, enabled in
                if !enabled { NSCursor.arrow.set() }
            }
            .accessibilityHidden(true)
    }

    /// Both panes' minimums, floored at 0. `min`/`max` rather than a range:
    /// on a width-0 first layout pass the bounds are inverted.
    private func clamped(_ width: CGFloat, available: CGFloat) -> CGFloat {
        max(min(max(width, leadingMinWidth), available - Self.dividerWidth - trailingMinWidth), 0)
    }
}
