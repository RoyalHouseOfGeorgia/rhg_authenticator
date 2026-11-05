/// A question to confirm before acting: title, message and the button titles,
/// all display only. The model that asks holds the action and runs it when the
/// operator confirms, and the alternate action, if any, when the operator
/// picks the third button.
public struct Confirmation: Sendable, Equatable {
    public var title: String
    public var message: String
    public var confirmTitle: String
    public var cancelTitle: String
    /// A third button's title (nil: none), answered with the model's `alternate()`.
    public var alternateTitle: String?
    /// The confirm button discards something: give it the destructive role,
    /// and Return to no button.
    public var isDestructive: Bool

    public init(
        title: String, message: String, confirmTitle: String, cancelTitle: String = "Cancel",
        alternateTitle: String? = nil, isDestructive: Bool = false
    ) {
        self.title = title
        self.message = message
        self.confirmTitle = confirmTitle
        self.cancelTitle = cancelTitle
        self.alternateTitle = alternateTitle
        self.isDestructive = isDestructive
    }

    /// The question's buttons in the order they are added to the dialog:
    /// confirm, Cancel, then the alternate, if any, in every question.
    /// NSAlert shows the first rightmost and each later one to its left, so
    /// the window sheet reads, left to right, [alternate] [Cancel] [confirm]
    /// (Delete Entry…: [Revoke Instead] [Cancel] [Delete]), the Mac layout
    /// of [Don't Save] [Cancel] [Save]. `isDestructive` changes only the key
    /// equivalents: in a destructive question no button has Return, and
    /// Cancel has Escape.
    public var buttonRoles: [ConfirmChoice] {
        let alternate: [ConfirmChoice] = alternateTitle == nil ? [] : [.alternate]
        return [.confirm, .cancel] + alternate
    }

    /// The key equivalent to give the button with `role`, or nil to keep
    /// NSAlert's own (Return on the first button added, confirm). Cancel
    /// always has Escape (NSAlert gives it only to a button titled
    /// "Cancel"); in a destructive question no other button has a key, so
    /// Return destroys nothing. Return does nothing there rather than
    /// cancel (as Enter does on Windows): a button has one key, and Cancel
    /// keeps Escape.
    public func keyEquivalent(for role: ConfirmChoice) -> String? {
        if role == .cancel {
            return "\u{1b}"
        }
        return isDestructive ? "" : nil
    }

    /// Whether the button with `role` is marked destructive: confirm, in a
    /// destructive question.
    public func hasDestructiveAction(for role: ConfirmChoice) -> Bool {
        isDestructive && role == .confirm
    }

    /// The answer of the button at `index` in `buttonRoles`; any other index
    /// (the dialog closed some other way) is Cancel.
    public func choice(forButtonAt index: Int) -> ConfirmChoice {
        let roles = buttonRoles
        return roles.indices.contains(index) ? roles[index] : .cancel
    }
}

/// The operator's answer to a `Confirmation`: its confirm button, its
/// alternate button, or Cancel (also any other way the question closed).
public enum ConfirmChoice: Sendable, Equatable {
    case confirm
    case alternate
    case cancel
}
