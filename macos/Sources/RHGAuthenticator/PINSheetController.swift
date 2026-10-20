import AppKit
import Observation
import RHGModels

/// The YubiKey PIN prompt, an AppKit sheet shown while the model's `request`
/// is non-nil. AppKit rather than SwiftUI because it must stack on whatever
/// sheet is already up (SwiftUI shows one sheet per window). The PIN goes
/// from the field to the model only; it is never logged.
@MainActor
final class PINSheetController: NSObject, NSTextFieldDelegate {
    private let prompt: PINPromptModel
    private let panel: NSPanel
    private let field = NSSecureTextField()
    private let hintLabel = NSTextField(labelWithString: "")
    private let rememberBox = NSButton(checkboxWithTitle: PINPromptModel.rememberLabel, target: nil, action: nil)
    /// The request on screen; nil while the sheet is closed.
    private var shownRequestId: UInt64?

    init(prompt: PINPromptModel) {
        self.prompt = prompt
        panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 200),
            styleMask: [.titled], backing: .buffered, defer: true)
        super.init()
        buildContent()
        observe()
    }

    // MARK: Observation

    /// Shows, refreshes or closes the sheet for the current request, and
    /// re-arms itself for the next change (onChange fires once, before the
    /// change lands, so the update runs on the next main-actor turn).
    private func observe() {
        let requestId = withObservationTracking {
            prompt.request?.requestId
        } onChange: {
            // The controller lives as long as the app; a strong capture is fine.
            Task { @MainActor in self.observe() }
        }
        update(requestId: requestId)
    }

    private func update(requestId: UInt64?) {
        guard requestId != shownRequestId else { return }
        guard requestId != nil else {
            close()
            return
        }
        let replacing = shownRequestId != nil
        shownRequestId = requestId
        resetFields()
        if replacing {
            _ = panel.makeFirstResponder(field)
        } else {
            show()
        }
    }

    private func resetFields() {
        field.stringValue = ""
        hintLabel.stringValue = prompt.hint
        rememberBox.state = prompt.remember ? .on : .off
    }

    /// Attaches the sheet to the window panels and alerts attach to
    /// (`FilePanel.parentWindow`: the main window's deepest sheet), so it
    /// stacks over any sheet already shown. Without a window it shows as a
    /// standalone panel.
    private func show() {
        if let parent = FilePanel.parentWindow {
            if parent.isMiniaturized {
                parent.deminiaturize(nil)
            }
            parent.beginSheet(panel, completionHandler: nil)
        } else {
            panel.center()
            panel.makeKeyAndOrderFront(nil)
        }
        _ = panel.makeFirstResponder(field)
        if !NSApp.isActive {
            _ = NSApp.requestUserAttention(.criticalRequest)
        }
    }

    private func close() {
        shownRequestId = nil
        field.stringValue = ""
        if let parent = panel.sheetParent {
            parent.endSheet(panel)
        } else {
            panel.orderOut(nil)
        }
    }

    // MARK: Actions

    @objc private func okPressed(_ sender: Any?) {
        prompt.pin = field.stringValue
        prompt.remember = rememberBox.state == .on
        let prompt = prompt
        Task { await prompt.submit() }
    }

    @objc private func cancelPressed(_ sender: Any?) {
        let prompt = prompt
        Task { await prompt.cancel() }
    }

    // MARK: NSTextFieldDelegate

    /// Passes each edit to the model, which caps the PIN to the core's byte
    /// limit; a capped PIN is written back to the field.
    func controlTextDidChange(_ obj: Notification) {
        prompt.pin = field.stringValue
        if field.stringValue != prompt.pin {
            field.stringValue = prompt.pin
        }
    }

    /// Return and Escape in the field: OK and Cancel.
    func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool {
        switch commandSelector {
        case #selector(NSResponder.insertNewline(_:)):
            okPressed(nil)
            return true
        case #selector(NSResponder.cancelOperation(_:)):
            cancelPressed(nil)
            return true
        default:
            return false
        }
    }

    // MARK: Layout

    private func buildContent() {
        panel.title = PINPromptModel.title
        panel.isReleasedWhenClosed = false

        // A sheet shows no title bar, so the title is repeated in the content.
        let titleLabel = NSTextField(labelWithString: PINPromptModel.title)
        titleLabel.font = NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)
        let promptLabel = NSTextField(labelWithString: PINPromptModel.prompt)

        field.placeholderString = PINPromptModel.placeholder
        field.delegate = self
        hintLabel.textColor = .secondaryLabelColor
        hintLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)

        let okButton = NSButton(title: PINPromptModel.okTitle, target: self, action: #selector(okPressed(_:)))
        okButton.keyEquivalent = "\r"
        let cancelButton = NSButton(
            title: PINPromptModel.cancelTitle, target: self, action: #selector(cancelPressed(_:)))
        cancelButton.keyEquivalent = "\u{1b}"
        let buttons = NSStackView()
        buttons.orientation = .horizontal
        buttons.addView(cancelButton, in: .trailing)
        buttons.addView(okButton, in: .trailing)

        let stack = NSStackView(views: [titleLabel, promptLabel, field, hintLabel, rememberBox, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.setCustomSpacing(16, after: rememberBox)
        stack.translatesAutoresizingMaskIntoConstraints = false

        let container = NSView()
        container.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -20),
            stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 20),
            stack.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -20),
            stack.widthAnchor.constraint(equalToConstant: 320),
            field.widthAnchor.constraint(equalTo: stack.widthAnchor),
            buttons.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
        panel.contentView = container
        container.layoutSubtreeIfNeeded()
        panel.setContentSize(container.fittingSize)
        panel.initialFirstResponder = field
    }
}
