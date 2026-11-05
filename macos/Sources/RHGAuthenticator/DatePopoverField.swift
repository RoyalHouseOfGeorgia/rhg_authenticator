import SwiftUI

/// A date field that shows the date once, as YYYY-Mon-DD (`text`), on a
/// button that opens a graphical picker in a popover. The core signs and
/// stores UTC calendar dates, so the picker shows and edits dates in UTC.
/// Disabling it (`.disabled`, or hiding its tab) also closes the picker.
@MainActor
struct DatePopoverField: View {
    /// The picker's label, read by VoiceOver.
    let title: String
    @Binding var date: Date
    /// The date as the model formats it; "" leaves the button blank.
    let text: String
    @State private var isPicking = false
    @Environment(\.isEnabled) private var isEnabled

    var body: some View {
        Button {
            isPicking = true
        } label: {
            Text(text)
                .monospacedDigit()
                // Keeps a blank button (no date) as wide as a dated one.
                .frame(minWidth: 90)
        }
        .accessibilityLabel(title)
        .accessibilityValue(text)
        .popover(isPresented: $isPicking) {
            DatePicker(title, selection: $date, displayedComponents: .date)
                .datePickerStyle(.graphical)
                .labelsHidden()
                .utcCalendar()
                .padding(12)
        }
        // A tab switch (⌘1–⌘5) disables the hidden tab but doesn't close a
        // popover on its own.
        .onChange(of: isEnabled) { _, enabled in
            if !enabled {
                isPicking = false
            }
        }
    }
}
