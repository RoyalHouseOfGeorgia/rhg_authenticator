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
    /// The confirm button discards something (give it the destructive role).
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
}
